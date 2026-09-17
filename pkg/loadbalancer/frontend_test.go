// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
)

func TestLookupFrontendByTuple(t *testing.T) {
	db := statedb.New()
	fes, err := NewFrontendsTable(DefaultConfig, db)
	require.NoError(t, err, "NewFrontendsTable")

	var addr L3n4Addr
	addr.ParseFromString("10.0.0.1:80/TCP")

	wtxn := db.WriteTxn(fes)
	fe := &Frontend{
		FrontendParams: FrontendParams{Address: addr},
	}
	fes.Insert(wtxn, fe)
	txn := wtxn.Commit()

	fe2, found := LookupFrontendByTuple(txn, fes, addr.AddrCluster(), addr.Protocol(), addr.Port(), addr.Scope())
	require.True(t, found)
	require.NotNil(t, fe2)
	require.Equal(t, fe, fe2)

	var addr2 L3n4Addr
	addr2.ParseFromString("10.0.0.2:80/TCP")
	fe2, found = LookupFrontendByTuple(txn, fes, addr2.AddrCluster(), addr2.Protocol(), addr2.Port(), addr2.Scope())
	require.False(t, found)
	require.Nil(t, fe2)
}

func TestLookupFrontendByID(t *testing.T) {
	db := statedb.New()
	fes, err := NewFrontendsTable(DefaultConfig, db)
	require.NoError(t, err, "NewFrontendsTable")

	var addr1, addr2, addr3 L3n4Addr
	addr1.ParseFromString("10.0.0.1:80/TCP")
	addr2.ParseFromString("10.0.0.2:80/TCP")
	addr3.ParseFromString("10.0.0.3:80/TCP")

	wtxn := db.WriteTxn(fes)
	fe1 := &Frontend{FrontendParams: FrontendParams{Address: addr1, ServiceName: NewServiceName("default", "svc1")}, ID: 100}
	fes.Insert(wtxn, fe1)
	// Two frontends with ID 0 (not a reconciliation candidate).
	fes.Insert(wtxn, &Frontend{FrontendParams: FrontendParams{Address: addr2, ServiceName: NewServiceName("default", "svc2")}, ID: 0})
	fes.Insert(wtxn, &Frontend{FrontendParams: FrontendParams{Address: addr3, ServiceName: NewServiceName("default", "svc3")}, ID: 0})
	txn := wtxn.Commit()

	got, found := LookupFrontendByID(txn, fes, ServiceID(100))
	require.True(t, found)
	require.Equal(t, fe1, got)

	_, found = LookupFrontendByID(txn, fes, ServiceID(200))
	require.False(t, found, "no frontend has ID 200")

	// ID 0 must never resolve, even though frontends with ID 0 exist.
	_, found = LookupFrontendByID(txn, fes, ServiceID(0))
	require.False(t, found, "ID 0 must always report not-found")
}
