// client_test.go - Cryptographic client tests.
// Copyright (C) 2019  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package crypto

import (
	"testing"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

func TestClientBasics(t *testing.T) {
	require := require.New(t)

	epoch := uint64(1234567)
	sharedRandom := [64]byte{}
	_, err := rand.Reader.Read(sharedRandom[:])
	require.NoError(err)
	passphrase := []byte("bridge traffic is busy tonight")
	payload1 := []byte("This is the payload1")
	payload2 := []byte("This is the payload2")

	// create client1 and client2
	client1, err := NewClient(passphrase, sharedRandom[:], epoch)
	require.NoError(err)

	client2, err := NewClient(passphrase, sharedRandom[:], epoch)
	require.NoError(err)

	// both clients generate a t1 message
	client1T1, err := client1.GenerateType1Message(epoch, sharedRandom[:], payload1)
	require.NoError(err)

	client2T1, err := client2.GenerateType1Message(epoch, sharedRandom[:], payload2)
	require.NoError(err)
	t.Logf("client2 t1 %x", client2T1)

	// client2 decodes the t1 message from client1
	client1T1Alpha, client1T1Beta, _, err := decodeT1Message(client1T1)
	require.NoError(err)

	// client2 processes the alpha portion of the received t1 message...
	// generating a t2 message
	client2T2, client1B1, err := client2.ProcessType1MessageAlpha(client1T1Alpha, sharedRandom[:], epoch)
	require.NoError(err)

	// client1 decodes the t2 message from client2
	client1CandidateKey, err := client1.GetCandidateKey(client2T2, client1B1, epoch, sharedRandom[:])
	require.NoError(err)

	// test that the candidate key is client2's s1
	require.Equal(client1CandidateKey, client2.s1[:])
	t.Logf("client1T1Beta %x", client1T1Beta)

	b2, err := decryptT1Beta(client1CandidateKey, client1T1Beta)
	require.NoError(err)
	t.Logf("b2 %x", b2)
}
