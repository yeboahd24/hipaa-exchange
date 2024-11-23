package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
	} `yaml:"database"`

	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		TLS struct {
			Enabled   bool   `yaml:"enabled"`
			CertFile  string `yaml:"cert_file"`
			KeyFile   string `yaml:"key_file"`
		} `yaml:"tls"`
	} `yaml:"server"`

	// Add more configuration sections as needed
}

func Load() (*Config, error) {
	// Look for config in multiple locations
	configPaths := []string{
		"./configs/config.yaml",
		"../configs/config.yaml",
		"/etc/hipaa-exchange/config.yaml",
	}

	var config Config
	for _, path := range configPaths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}

		configFile, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}

		err = yaml.Unmarshal(configFile, &config)
		if err != nil {
			return nil, err
		}

		return &config, nil
	}

	return nil, fmt.Errorf("no configuration file found")
}

func LoadConfig() (*Config, error) {
	return Load()
}
