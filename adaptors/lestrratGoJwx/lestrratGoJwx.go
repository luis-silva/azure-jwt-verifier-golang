/*******************************************************************************
 * Copyright 2018 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

package lestrratGoJwx

import (
	"encoding/json"
	"sync"
	"time"

	jwa "github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	jws "github.com/lestrrat-go/jwx/jws"
	"github.com/luis-silva/azure-jwt-verifier-golang/adaptors"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

var jwkSetCache *cache.Cache = cache.New(5*time.Minute, 10*time.Minute)
var jwkSetMu = &sync.Mutex{}

func getJwkSet(jwkUri string) (*jwk.Set, error) {
	jwkSetMu.Lock()
	defer jwkSetMu.Unlock()

	if x, found := jwkSetCache.Get(jwkUri); found {
		return x.(*jwk.Set), nil
	}

	jwkSet, err := jwk.FetchHTTP(jwkUri)

	if err != nil {
		return nil, err
	}

	jwkSetCache.SetDefault(jwkUri, jwkSet)

	return jwkSet, nil
}

type LestrratGoJwx struct {
	JWKSet jwk.Set
}

func (lgj LestrratGoJwx) New() adaptors.Adaptor {
	return lgj
}

func (lgj LestrratGoJwx) GetKey(jwkUri string) {
	return
}

func (lgj LestrratGoJwx) Decode(jwt string, jwkUri string) (interface{}, error) {
	jwkSet, err := getJwkSet(jwkUri)

	if err != nil {
		return nil, err
	}

	token, err := VerifyWithJWKSet([]byte(jwt), jwkSet, nil)

	if err != nil {
		return nil, err
	}

	var claims interface{}

	json.Unmarshal(token, &claims)

	return claims, nil

}

func VerifyWithJWKSet(buf []byte, keyset *jwk.Set, keyaccept jws.JWKAcceptFunc) (payload []byte, err error) {

	if keyaccept == nil {
		keyaccept = jws.DefaultJWKAcceptor
	}

	for _, key := range keyset.Keys {
		if !keyaccept(key) {
			continue
		}

		payload, err := VerifyWithJWK(buf, key)
		if err == nil {
			return payload, nil
		}
	}

	return nil, errors.Wrap(err, "failed to verify with any of the keys")
}

func VerifyWithJWK(buf []byte, key jwk.Key) (payload []byte, err error) {

	keyval, err := key.Materialize()
	if err != nil {
		return nil, errors.Wrap(err, `failed to materialize jwk.Key`)
	}

	alg := key.Algorithm()
	if alg == "" && key.KeyType().String() == "RSA" {
		alg = "RS256"
	}

	payload, err = jws.Verify(buf, jwa.SignatureAlgorithm(alg), keyval)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify message")
	}

	return payload, nil
}
