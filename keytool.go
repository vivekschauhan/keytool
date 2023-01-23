package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Config the configuration for the KeyTool
type Config struct {
	PrivateKey string `mapstructure:"private_key"`
	PublicKey  string `mapstructure:"public_key"`
	DataFile   string `mapstructure:"data_file"`
	Decrypt    bool   `mapstructure:"decrypt"`
	Level      string `mapstructure:"log_level"`
	Format     string `mapstructure:"log_format"`
}

// result, err := encrypt(parsePublicKey(key), "RSA-OAEP", data)
// if err != nil {
// 	log.Fatal(err)
// }
// fmt.Printf("%s\n", result)

var cfg = &Config{}

// NewRootCmd creates a new cobra.Command
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "keytool",
		Short:   "The Tool for encrypting and decrypting content with specified keys",
		Version: "0.0.1",
		RunE:    run,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initViperConfig(cmd)
		},
	}

	initFlags(cmd)

	return cmd
}

func initFlags(cmd *cobra.Command) {
	cmd.Flags().String("private_key", "", "private key used for decrypting the content")
	cmd.Flags().String("public_key", "", "public key used for encrypting the content")
	cmd.Flags().String("data_file", "", "the data file that will be encrypted/decrypted")
	cmd.Flags().Bool("decrypt", false, "flag for decrypting the content")
	cmd.Flags().String("log_level", "info", "log level")
	cmd.Flags().String("log_format", "json", "line or json")
}

func initViperConfig(cmd *cobra.Command) error {
	v := viper.New()
	v.AutomaticEnv()
	bindFlagsToViperConfig(cmd, v)

	err := v.Unmarshal(cfg)
	if err != nil {
		return err
	}

	return nil
}

// bindFlagsToViperConfig - For each flag, look up its corresponding env var, and use the env var if the flag is not set.
func bindFlagsToViperConfig(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// name := strings.ToUpper(f.Name)
		if err := v.BindPFlag(f.Name, f); err != nil {
			panic(err)
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
			if err != nil {
				panic(err)
			}
		}
	})
}

func run(_ *cobra.Command, _ []string) error {
	logger, err := getLogger(cfg.Level, cfg.Format)
	if err != nil {
		return err
	}
	if !cfg.Decrypt {
		logger.Info(fmt.Sprintf("Encrypting %s with %s", cfg.DataFile, cfg.PublicKey))
		pemFileContent, err := ioutil.ReadFile(cfg.PublicKey)
		if err != nil {
			panic(err)
		}

		publicKey := parsePublicKey(pemFileContent)

		data, err := ioutil.ReadFile(cfg.DataFile)
		if err != nil {
			panic(err)
		}
		encData, err := encrypt(publicKey, "RSA-OAEP", data)
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile(cfg.DataFile+".encrypted", []byte(encData), 0666)
		logger.Info(fmt.Sprintf("Encrypted base64 encoded content written to %s", cfg.DataFile+".encrypted"))
	}
	return nil
}

func parsePublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse private key: " + err.Error())
	}

	return pk.(*rsa.PublicKey)
}

func encrypt(pk *rsa.PublicKey, alg string, data []byte) (string, error) {
	enc := func(v []byte) (string, error) {
		switch alg {
		case "RSA-OAEP":
			bts, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, v, nil)
			return base64.StdEncoding.EncodeToString(bts), err
		case "PKCS":
			bts, err := rsa.EncryptPKCS1v15(rand.Reader, pk, v)
			return base64.StdEncoding.EncodeToString(bts), err
		default:
			return "", fmt.Errorf("unexpected algorithm")
		}
	}

	bts, err := enc(data)
	return bts, err
}
