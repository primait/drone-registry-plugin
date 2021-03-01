package plugin

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecrpublic"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	proxyEndpointScheme = "https://"
	programName         = "docker-credential-ecr-login"
	ecrPublicName       = "public.ecr.aws"
	ecrPublicEndpoint   = proxyEndpointScheme + ecrPublicName
)

var ecrPattern = regexp.MustCompile(`(^[a-zA-Z0-9][a-zA-Z0-9-_]*)\.dkr\.ecr(-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.amazonaws\.com(\.cn)?$`)

type Service string

const (
	ServiceECR       Service = "ecr"
	ServiceECRPublic Service = "ecr-public"
)

type Auth struct {
	ProxyEndpoint string
	Username      string
	Password      string
}

// Registry in ECR
type Registry struct {
	Service Service
	ID      string
	FIPS    bool
	Region  string
}

type defaultClient struct {
	ecrClient       ECRAPI
	ecrPublicClient ECRPublicAPI
}

type ECRAPI interface {
	GetAuthorizationToken(*ecr.GetAuthorizationTokenInput) (*ecr.GetAuthorizationTokenOutput, error)
}

type ECRPublicAPI interface {
	GetAuthorizationToken(*ecrpublic.GetAuthorizationTokenInput) (*ecrpublic.GetAuthorizationTokenOutput, error)
}

// GetCredentials returns username, password, and proxyEndpoint
func (c *defaultClient) GetCredentials(serverURL string) (*Auth, error) {
	registry, err := ExtractRegistry(serverURL)
	if err != nil {
		return nil, err
	}
	logrus.
		WithField("service", registry.Service).
		WithField("registry", registry.ID).
		WithField("region", registry.Region).
		WithField("serverURL", serverURL).
		Debug("Retrieving credentials")
	switch registry.Service {
	case ServiceECR:
		return c.GetCredentialsByRegistryID(registry.ID)
	case ServiceECRPublic:
		return c.GetPublicCredentials()
	}
	return nil, fmt.Errorf("unknown service %q", registry.Service)
}

func ExtractRegistry(input string) (*Registry, error) {
	if strings.HasPrefix(input, proxyEndpointScheme) {
		input = strings.TrimPrefix(input, proxyEndpointScheme)
	}
	serverURL, err := url.Parse(proxyEndpointScheme + input)
	if err != nil {
		return nil, err
	}
	if serverURL.Hostname() == ecrPublicName {
		return &Registry{
			Service: ServiceECRPublic,
		}, nil
	}
	matches := ecrPattern.FindStringSubmatch(serverURL.Hostname())
	if len(matches) == 0 {
		return nil, fmt.Errorf(programName + " can only be used with Amazon Elastic Container Registry.")
	} else if len(matches) < 3 {
		return nil, fmt.Errorf("%q is not a valid repository URI for Amazon Elastic Container Registry.", input)
	}
	return &Registry{
		Service: ServiceECR,
		ID:      matches[1],
		FIPS:    matches[2] == "-fips",
		Region:  matches[3],
	}, nil
}

// GetCredentialsByRegistryID returns username, password, and proxyEndpoint
func (c *defaultClient) GetCredentialsByRegistryID(registryID string) (*Auth, error) {
	auth, err := c.getAuthorizationToken(registryID)
	return auth, err
}

func (c *defaultClient) GetPublicCredentials() (*Auth, error) {
	auth, err := c.getPublicAuthorizationToken()
	return auth, err
}

func (c *defaultClient) getAuthorizationToken(registryID string) (*Auth, error) {
	var input *ecr.GetAuthorizationTokenInput
	if registryID == "" {
		logrus.Debug("Calling ECR.GetAuthorizationToken for default registry")
		input = &ecr.GetAuthorizationTokenInput{}
	} else {
		logrus.WithField("registry", registryID).Debug("Calling ECR.GetAuthorizationToken")
		input = &ecr.GetAuthorizationTokenInput{
			RegistryIds: []*string{aws.String(registryID)},
		}
	}

	output, err := c.ecrClient.GetAuthorizationToken(input)
	if err != nil || output == nil {
		if err == nil {
			if registryID == "" {
				err = fmt.Errorf("missing AuthorizationData in ECR response for default registry")
			} else {
				err = fmt.Errorf("missing AuthorizationData in ECR response for %s", registryID)
			}
		}
		return nil, errors.Wrap(err, "ecr: Failed to get authorization token")
	}

	for _, authData := range output.AuthorizationData {
		if authData.ProxyEndpoint != nil && authData.AuthorizationToken != nil {
			auth, err := extractToken(*authData.AuthorizationToken, *authData.ProxyEndpoint)
			if err != nil {
				return nil, err
			}
			return auth, nil
		}
	}
	if registryID == "" {
		return nil, fmt.Errorf("No AuthorizationToken found for default registry")
	}
	return nil, fmt.Errorf("No AuthorizationToken found for %s", registryID)
}

func (c *defaultClient) getPublicAuthorizationToken() (*Auth, error) {
	var input *ecrpublic.GetAuthorizationTokenInput

	output, err := c.ecrPublicClient.GetAuthorizationToken(input)
	if err != nil {
		return nil, errors.Wrap(err, "ecr: failed to get authorization token")
	}
	if output == nil || output.AuthorizationData == nil {
		return nil, fmt.Errorf("ecr: missing AuthorizationData in ECR Public response")
	}
	authData := output.AuthorizationData
	token, err := extractToken(aws.StringValue(authData.AuthorizationToken), ecrPublicEndpoint)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func extractToken(token string, proxyEndpoint string) (*Auth, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token")
	}

	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token: expected two parts, got %d", len(parts))
	}

	return &Auth{
		Username:      parts[0],
		Password:      parts[1],
		ProxyEndpoint: proxyEndpoint,
	}, nil
}