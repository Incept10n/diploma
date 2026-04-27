package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var cronController *CronController
var fileMonitor *FileMonitor

func main() {
	var kubeconfig string
	var master string
	var mode string

	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&master, "master", "", "master url")
	flag.StringVar(&mode, "mode", "controller", "running mode: controller or agent")
	flag.Parse()

	log.Printf("Starting in %s mode", mode)

	config, err := buildConfig(master, kubeconfig)
	if err != nil {
		log.Fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Next step - loading the security config")
	securityConfig, err := loadSecurityConfig()
	if err != nil {
		log.Printf("Warning: Could not load security config, using defaults: %v", err)
		log.Fatal(err)
	}

	if securityConfig.Cron.Enabled {
		cronController = NewCronController(clientset, config, securityConfig)
	}

	if securityConfig.FileMonitoring.Enabled || securityConfig.Secrets.Enabled {
		fileMonitor = NewFileMonitor(clientset, config, securityConfig)
	}

	// Start
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received termination signal, shutting down...")
		cancel()
	}()

	log.Println("Starting Kubernetes Security Controller")

	if mode == "agent" {
		nodeName := os.Getenv("NODE_NAME")
		if nodeName == "" {
			log.Fatal("NODE_NAME environment variable is required for agent mode")
		}
		log.Printf("Starting agent mode for node: %s", nodeName)

		var wg sync.WaitGroup

		// 1) Cron monitoring
		if securityConfig.Cron.Enabled {
			wg.Add(1)
			go func() {
				defer wg.Done()
				log.Printf("Cron monitor enabled. Interval: %v", securityConfig.Cron.MonitoringInterval)
				cronController.StartAgentMonitoring(ctx, nodeName)
			}()
		}

		// 2) File + secrets monitoring
		if securityConfig.FileMonitoring.Enabled || securityConfig.Secrets.Enabled {
			wg.Add(1)
			go func() {
				defer wg.Done()
				log.Printf("File/Secrets monitor enabled. File interval: %v", securityConfig.FileMonitoring.MonitoringInterval)
				fileMonitor.StartAgentMonitoring(ctx, nodeName)
			}()
		}

		if securityConfig.FalcoWebhook.Enabled {
			wg.Add(1)
			go func() {
				defer wg.Done()

				addr := securityConfig.FalcoWebhook.ListenAddr
				if addr == "" {
					addr = ":2801"
				}

				secret := securityConfig.FalcoWebhook.Secret
				server := NewFalcoWebhookServer(clientset, config, secret)

				log.Printf("Falco webhook enabled. Listening on %s", addr)
				server.Start(ctx, addr)
			}()
		} else {
			log.Printf("Falco webhook disabled in config")
		}

		wg.Wait()
	} else {
		log.Fatal("controller mode is not implemented yet")
	}
}

func buildConfig(masterUrl, kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags(masterUrl, kubeconfigPath)
	}
	return rest.InClusterConfig()
}
