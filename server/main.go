package wboxserver

import (
	"bufio"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/foxcpp/wirebox"
	"github.com/foxcpp/wirebox/linkmgr"
	"golang.org/x/sys/unix"
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

func Main() int {
	// Read configuration and command line flags.
	cfgPath := flag.String("config", "wboxd.toml", "path to configuration file")
	debug := flag.Bool("debug", false, "enable debug log")
	flag.Parse()
	if !*debug {
		debugLog = log.New(ioutil.Discard, "", 0)
	}

	cfgF, err := os.Open(*cfgPath)
	if err != nil {
		logErr(err)
		return 2
	}
	var cfg SrvConfig
	if _, err := toml.DecodeReader(cfgF, &cfg); err != nil {
		log.Println("error: config load:", err)
		return 2
	}
	if err := cfg.Validate(); err != nil {
		logErr(err)
		return 2
	}
	log.Println("server public key:", cfg.PrivateKey.PublicFromPrivate())

	var clientKeys []wirebox.PeerKey
	if cfg.AuthFile != "" {
		clientKeys, err = readKeyList(cfg.AuthFile)
		if err != nil {
			logErr(err)
			return 2
		}
	} else {
		for encoded := range cfg.Clients {
			pubKey, err := wirebox.NewPeerKey(encoded)
			if err != nil {
				logErr(err)
				return 2
			}
			clientKeys = append(clientKeys, pubKey)
		}
	}
	if len(clientKeys) == 0 {
		log.Println("error: no client keys configured")
		return 2
	}
	log.Println(len(clientKeys), "client keys")

	clientCfgs, err := buildClientConfigs(cfg, clientKeys)
	if err != nil {
		logErr(err)
		return 1
	}

	m, err := linkmgr.NewManager()
	if err != nil {
		log.Println("error: link mngr init:", err)
		return 1
	}

	_, newClientLinks, err := configurePeerTuns(m, cfg, clientKeys, clientCfgs)
	if err != nil {
		logErr(err)
		return 1
	}
	defer func() {
		for _, l := range newClientLinks {
			if err := m.DelLink(l.Index()); err != nil {
				logErr(err)
			} else {
				log.Println("deleted link", l.Name())
			}
		}
	}()

	// Create configuration interface.
	confLink, created, err := createConfLink(m, cfg, clientKeys)
	if err != nil {
		logErr(err)
		return 1
	}
	if created {
		log.Println("created configuration link", confLink.Name())
		defer func() {
			logErr(m.DelLink(confLink.Index()))
			log.Println("deleted link", confLink.Name())
		}()
	} else {
		log.Println("using existing link", confLink.Name(), "for configuration")
	}

	// Listen on SolictIPv6.
	c, err := net.ListenUDP("udp6", &net.UDPAddr{
		IP:   wirebox.SolictIPv6,
		Port: wirebox.SolictPort,
		Zone: strconv.Itoa(confLink.Index()),
	})
	if err != nil {
		logErr(err)
		return 1
	}
	log.Println("listening on", c.LocalAddr())

	stopServe := make(chan struct{}, 1)
	go serve(stopServe, c, clientCfgs)
	defer func() {
		<-stopServe
	}()
	defer c.Close()
	defer func() {
		stopServe <- struct{}{}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGINT, unix.SIGHUP, unix.SIGTERM)

	sig := <-ch
	log.Println("received signal:", sig)

	return 0
}
