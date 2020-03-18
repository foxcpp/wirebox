package wboxserver

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/foxcpp/wirebox"
	"github.com/foxcpp/wirebox/linkmgr"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	debugLog = log.New(os.Stderr, "debug: ", log.LstdFlags)
)

func logErr(err error) {
	if err == nil {
		return
	}
	log.Println("error:", err)
}

func readKeyList(path string) ([]wirebox.PeerKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var res []wirebox.PeerKey
	scnr := bufio.NewScanner(f)
	for scnr.Scan() {
		text := strings.TrimSpace(scnr.Text())
		if len(text) == 0 {
			continue
		}
		if strings.HasPrefix(text, "#") {
			continue
		}

		k, err := wirebox.NewPeerKey(text)
		if err != nil {
			return nil, err
		}
		res = append(res, k)
	}
	if err := scnr.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func loadConfig(path string) (SrvConfig, error) {
	cfgF, err := os.Open(path)
	if err != nil {
		return SrvConfig{}, fmt.Errorf("config load: %w", err)
	}
	var cfg SrvConfig
	if _, err := toml.DecodeReader(cfgF, &cfg); err != nil {
		return SrvConfig{}, fmt.Errorf("config load: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return SrvConfig{}, fmt.Errorf("config load: %w", err)
	}
	log.Println("server public key:", cfg.PrivateKey.PublicFromPrivate())
	return cfg, nil
}

func clientKeys(cfg SrvConfig) ([]wirebox.PeerKey, error) {
	var (
		clientKeys []wirebox.PeerKey
		err        error
	)
	if cfg.AuthFile != "" {
		clientKeys, err = readKeyList(cfg.AuthFile)
		if err != nil {
			return nil, fmt.Errorf("client keys: %w", err)
		}
	} else {
		for encoded := range cfg.Clients {
			pubKey, err := wirebox.NewPeerKey(encoded)
			if err != nil {
				return nil, fmt.Errorf("client keys: %w", err)
			}
			clientKeys = append(clientKeys, pubKey)
		}
	}
	if len(clientKeys) == 0 {
		return nil, fmt.Errorf("client keys: no keys")
	}
	log.Println(len(clientKeys), "client keys")
	return clientKeys, nil
}

type Server struct {
	m linkmgr.Manager

	MasterLink linkmgr.Link

	// Whether the ConfLink was created on startup and hence should be removed
	// afterwards.
	DelMasterLink bool

	Cfg SrvConfig

	// List of tunnel interfaces configured for clients.
	Tunnels []linkmgr.Link

	// List of newly created tunnel interface. These should be deleted on shutdown.
	NewTunnels []linkmgr.Link

	ClientCfgs  map[wgtypes.Key]ClientCfg
	SolictConns []*net.UDPConn
}

func initialize(m linkmgr.Manager, cfgPath string) (*Server, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}

	clientKeys, err := clientKeys(cfg)
	if err != nil {
		return nil, err
	}

	clientCfgs, err := buildClientConfigs(cfg, clientKeys)
	if err != nil {
		return nil, err
	}

	var (
		created    bool
		masterLink linkmgr.Link
	)

	if cfg.PtMP {
		masterLink, created, err = createMultipointLink(m, cfg, clientKeys, clientCfgs)
	} else {
		masterLink, created, err = createConfLink(m, cfg, clientKeys)
	}
	if err != nil {
		return nil, err
	}

	mainSolictConn, err := net.ListenUDP("udp6", &net.UDPAddr{
		IP:   wirebox.SolictIPv6,
		Port: wirebox.SolictPort,
		Zone: strconv.Itoa(masterLink.Index()),
	})
	if err != nil {
		if err := m.DelLink(masterLink.Index()); err != nil {
			log.Println("failed to delete link:", err)
		}
		return nil, err
	}

	var (
		clientLinks []linkmgr.Link
		newLinks    []linkmgr.Link
	)

	if !cfg.PtMP {
		clientLinks, newLinks, err = configurePeerTuns(m, cfg, clientKeys, clientCfgs)
		if err != nil {
			if err := m.DelLink(masterLink.Index()); err != nil {
				log.Println("failed to delete link:", err)
			}
			return nil, err
		}
	}

	solictConns := make([]*net.UDPConn, 0, len(clientLinks)+1)

	for _, l := range clientLinks {
		c, err := net.ListenUDP("udp6", &net.UDPAddr{
			IP:   wirebox.SolictIPv6,
			Port: wirebox.SolictPort,
			Zone: strconv.Itoa(l.Index()),
		})
		if err != nil {
			for _, sc := range solictConns {
				sc.Close()
			}
			for _, l := range newLinks {
				if err := m.DelLink(l.Index()); err != nil {
					log.Println("failed to delete link:", err)
				}
			}
			if err := m.DelLink(masterLink.Index()); err != nil {
				log.Println("failed to delete link:", err)
			}
			return nil, err
		}
		solictConns = append(solictConns, c)
	}
	solictConns = append(solictConns, mainSolictConn)

	return &Server{
		m:             m,
		Cfg:           cfg,
		MasterLink:    masterLink,
		DelMasterLink: created,
		Tunnels:       clientLinks,
		NewTunnels:    newLinks,
		ClientCfgs:    clientCfgs,
		SolictConns:   solictConns,
	}, nil
}

func (s *Server) GoServe() (stop func()) {
	log.Println("serving configurations for", len(s.ClientCfgs), "clients")

	wg := sync.WaitGroup{}
	stopServe := make(chan struct{}, 1)

	for _, sc := range s.SolictConns {
		sc := sc

		wg.Add(1)
		go func() {
			serve(stopServe, sc, s.ClientCfgs)
			wg.Done()
		}()
	}

	return func() {
		close(stopServe)
		for _, sc := range s.SolictConns {
			sc.Close()
		}
		wg.Wait()
	}
}

func (s *Server) Close() error {
	for _, l := range s.NewTunnels {
		if err := s.m.DelLink(l.Index()); err != nil {
			log.Println("error: failed to delete link:", err)
		}
	}
	if s.DelMasterLink {
		if err := s.m.DelLink(s.MasterLink.Index()); err != nil {
			log.Println("error: failed to delete link:", err)
		}
	}
	return nil
}

func Main() int {
	// Read configuration and command line flags.
	cfgPath := flag.String("config", "wboxd.toml", "path to configuration file")
	debug := flag.Bool("debug", false, "enable debug log")
	flag.Parse()
	if !*debug {
		debugLog = log.New(ioutil.Discard, "", 0)
	}

	m, err := linkmgr.NewManager()
	if err != nil {
		log.Println("error: link mngr init:", err)
		return 1
	}

	srv, err := initialize(m, *cfgPath)
	if err != nil {
		log.Println("error: initialization failed:", err)
		return 1
	}
	defer srv.Close()

	stop := srv.GoServe()
	defer stop()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGINT, unix.SIGHUP, unix.SIGTERM)

	sig := <-ch
	log.Println("received signal:", sig)

	return 0
}
