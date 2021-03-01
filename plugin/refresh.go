// Copyright 2018 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by the Drone Non-Commercial License
// that can be found in the LICENSE file.

package plugin

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecrpublic"
)

// refreshFunc refreshes an ecr registry username and password.
type refreshFunc func(registry *globalRegistry) error

type Options struct {
	Session  *session.Session
	Config   *aws.Config
	CacheDir string
}


func defaultRefreshFunc(r *globalRegistry) error {
	registry, err := ExtractRegistry(r.Address)
	if err != nil {
		return err
	}

	var creds *credentials.Credentials
	if r.Access != "" {
		creds = credentials.NewStaticCredentials(r.Access, r.Secret, "")
	}
	sess := session.New(&aws.Config{
		Region:      aws.String(registry.Region),
		Credentials: creds,
	})

	options := Options{Session: sess, Config: aws.NewConfig().WithRegion(registry.Region)}
	publicConfig := options.Config.Copy().WithRegion("us-east-1")
	defaultClient := &defaultClient{
		ecrClient:       ecr.New(options.Session, options.Config),
		ecrPublicClient: ecrpublic.New(options.Session, publicConfig),
	}

	auth, err := defaultClient.GetCredentials(r.Address)

	if err != nil {
		return err
	}

	r.Lock()
	r.Username = auth.Username
	r.Password = auth.Password
	r.expiry = time.Now().Add(time.Hour)
	r.Unlock()

	return nil
}