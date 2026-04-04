package main

import (
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"
)

type SecurityConfig struct {
	Cron    CronConfig    `yaml:"cron"`
	Logging LoggingConfig `yaml:"logging"`
}

type CronConfig struct {
	Enabled            bool          `yaml:"enabled"`
	MonitoringInterval time.Duration `yaml:"monitoringInterval"`
	MonitoredPaths     []string      `yaml:"monitoredPaths"`
	SuspiciousPatterns []string      `yaml:"suspiciousPatterns"`
	AllowedCommands    []string      `yaml:"allowedCommands"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

func loadSecurityConfig() (*SecurityConfig, error) {
	// Пытаемся загрузить из ConfigMap (внутри контейнера)
	configPath := "/config/security-config.yaml"
	if data, err := ioutil.ReadFile(configPath); err == nil {
		var config SecurityConfig
		if err := yaml.Unmarshal(data, &config); err == nil {
			// Конвертируем строку времени в time.Duration
			return &config, nil
		}
	}

	// Если ConfigMap недоступен, используем дефолтную конфигурацию
	return getDefaultSecurityConfig(), nil
}
