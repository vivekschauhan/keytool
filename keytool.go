package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/vivekschauhan/keytool/decrypt"
	"github.com/vivekschauhan/keytool/encrypt"
	"github.com/vivekschauhan/keytool/keys"
)

// Config the configuration for the KeyTool
type Config struct {
	PrivateKey      string `mapstructure:"private_key"`
	PublicKey       string `mapstructure:"public_key"`
	DataFile        string `mapstructure:"data_file"`
	Decrypt         bool   `mapstructure:"decrypt"`
	GenerateKeyPair bool   `mapstructure:"generate_keypair"`
	UseSymmetric    bool   `mapstructure:"use_symmetric"`
	UseJwe          bool   `mapstructure:"use_jwe"`
	Level           string `mapstructure:"log_level"`
	Format          string `mapstructure:"log_format"`
}

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
	cmd.Flags().Bool("use_symmetric", false, "flag for using symmetric key")
	cmd.Flags().Bool("use_jwe", false, "flag for using JWE")
	cmd.Flags().Bool("generate_keypair", false, "generate keypair")
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
		if err := v.BindPFlag(f.Name, f); err != nil {
			panic(err)
		}

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
	switch {
	case cfg.GenerateKeyPair:
		_, err := keys.CreateKeyPair()
		fmt.Println("Key generated")
		return err
	case cfg.Decrypt:
		logger.Info(fmt.Sprintf("Decrypting %s with %s", cfg.DataFile, cfg.PrivateKey))
		pemFileContent, err := os.ReadFile(cfg.PrivateKey)
		if err != nil {
			panic(err)
		}

		privateKey, err := keys.ParsePrivateKey(pemFileContent)
		if err != nil {
			panic(err)
		}

		msg, err := os.ReadFile(cfg.DataFile)
		if err != nil {
			panic(err)
		}

		data, err := decrypt.Decrypt(privateKey, "RSA-OAEP", "SHA256", string(msg), cfg.UseSymmetric, cfg.UseJwe)
		if err != nil {
			panic(err)
		}

		os.WriteFile(cfg.DataFile+".decrypted", []byte(data), 0666)
		logger.Info(fmt.Sprintf("Decrypted content written to %s", cfg.DataFile+".decrypted"))

	default:
		logger.Info(fmt.Sprintf("Encrypting %s with %s", cfg.DataFile, cfg.PublicKey))
		pemFileContent, err := os.ReadFile(cfg.PublicKey)
		if err != nil {
			panic(err)
		}

		publicKey, err := keys.ParsePublicKey(pemFileContent)
		if err != nil {
			panic(err)
		}

		data, err := os.ReadFile(cfg.DataFile)
		if err != nil {
			panic(err)
		}

		msg, err := encrypt.Encrypt(publicKey, "RSA-OAEP", "SHA256", string(data), cfg.UseSymmetric, cfg.UseJwe)
		if err != nil {
			panic(err)
		}

		os.WriteFile(cfg.DataFile+".encrypted", []byte(msg), 0666)
		logger.Info(fmt.Sprintf("Encrypted base64 encoded content written to %s", cfg.DataFile+".encrypted"))
	}
	return nil
}
