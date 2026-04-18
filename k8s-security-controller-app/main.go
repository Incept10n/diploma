package main

import (
	"context"
	"flag"
	"fmt"
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

	// Создаем конфигурацию для подключения к Kubernetes
	config, err := buildConfig(master, kubeconfig)
	if err != nil {
		log.Fatal(err)
	}

	// Создаем клиент Kubernetes
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// Загружаем конфигурацию безопасности
	log.Println("Next step - loading the security config")
	securityConfig, err := loadSecurityConfig()
	if err != nil {
		log.Printf("Warning: Could not load security config, using defaults: %v", err)
		log.Fatal(err)
	}

	// Создаем контроллер cron
	if securityConfig.Cron.Enabled {
		cronController = NewCronController(clientset, config, securityConfig)
	}

	if securityConfig.FileMonitoring.Enabled || securityConfig.Secrets.Enabled {
		fileMonitor = NewFileMonitor(clientset, config, securityConfig)
	}

	// Запускаем контроллер
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Обработка сигналов завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received termination signal, shutting down...")
		cancel()
	}()

	log.Println("Starting Kubernetes Security Controller - Cron Monitor")
	log.Printf("Monitoring interval: %v", securityConfig.Cron.MonitoringInterval)

	if mode == "agent" {
		// Агент мониторит только поды на своей ноде
		nodeName := os.Getenv("NODE_NAME")
		if nodeName == "" {
			log.Fatal("NODE_NAME environment variable is required for agent mode")
		}
		log.Printf("Starting agent mode for node: %s", nodeName)

		var wg sync.WaitGroup

		if securityConfig.Cron.Enabled {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cronController.StartAgentMonitoring(ctx, nodeName)
			}()
		}
		// if securityConfig.Cron.Enabled {
		// 	cronController.StartAgentMonitoring(ctx, nodeName)
		// }
		if securityConfig.FileMonitoring.Enabled || securityConfig.Secrets.Enabled {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fileMonitor.StartAgentMonitoring(ctx, nodeName)
			}()
		}

		wg.Wait()
	} else {
		os.Exit(1)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
