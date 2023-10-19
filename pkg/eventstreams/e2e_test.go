// Copyright © 2023 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package eventstreams

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/dbsql"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/wsclient"
	"github.com/hyperledger/firefly-common/pkg/wsserver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type testESConfig struct {
	Config1 string `json:"config1"`
}

func (tc *testESConfig) Scan(src interface{}) error {
	return fftypes.JSONScan(src, tc)
}

func (tc *testESConfig) Value() (driver.Value, error) {
	return fftypes.JSONValue(tc)
}

type testData struct {
	Field1 string `json:"field1"`
}

type testSource struct {
	started             chan struct{}
	startCount          int
	sequenceStartedWith string
}

func (ts *testSource) Validate(ctx context.Context, config *testESConfig) error {
	if config.Config1 == "" {
		return fmt.Errorf("config1 missing")
	}
	return nil
}

func (ts *testSource) Run(ctx context.Context, spec *EventStreamSpec[testESConfig], checkpointSequenceID string, deliver Deliver[testData]) error {
	batchNumber := 0
	ts.startCount++
	ts.sequenceStartedWith = checkpointSequenceID
	for {
		select {
		case <-ts.started:
		case <-ctx.Done():
			return fmt.Errorf("exiting due to cancelled context")
		}

		// Broadcast batches of 10 events...
		events := make([]*Event[testData], 10)
		for iEv := 0; iEv < 10; iEv++ {
			// With one message on each of 10 topics
			topic := fmt.Sprintf("topic_%d", iEv)
			events[iEv] = &Event[testData]{
				Topic:      topic,
				SequenceID: fmt.Sprintf("%.12d", batchNumber),
				Data: &testData{
					Field1: fmt.Sprintf("data_%d", batchNumber),
				},
			}
		}
		if deliver(events) == Exit {
			return nil
		}
		time.Sleep(1 * time.Millisecond)
		batchNumber++
	}
}

// This test demonstrates the runtime function of the event stream module through a simple test,
// using an SQLite database for CRUD operations on the persisted event streams,
// and a fake stream of events.
func TestE2E_DeliveryWebSockets(t *testing.T) {
	ctx, p, wss, wsc, done := setupE2ETest(t)

	ts := &testSource{started: make(chan struct{})}
	close(ts.started) // start delivery immediately - will block as no WS connected

	mgr, err := NewEventStreamManager[testESConfig, testData](ctx, GenerateConfig(ctx), p, wss, ts)
	assert.NoError(t, err)

	// Create a stream to sub-select one topic
	es1 := &EventStreamSpec[testESConfig]{
		Name:        ptrTo("stream1"),
		TopicFilter: ptrTo("topic_1"), // only one of the topics
		Type:        &EventStreamTypeWebSocket,
		BatchSize:   ptrTo(10),
	}
	created, err := mgr.UpsertStream(ctx, es1)
	assert.NoError(t, err)
	assert.True(t, created)

	// Connect our websocket and start it
	err = wsc.Connect()
	assert.NoError(t, err)
	err = wsc.Send(ctx, []byte(`{"type":"start","stream":"stream1"}`))
	assert.NoError(t, err)

	expectedNumber := 1
	for i := 0; i < 10; i++ {
		wsReceiveAck(ctx, t, wsc, func(batch *EventBatch[testData]) {
			// each batch should be 10
			assert.Len(t, batch.Events, 10)
			for _, e := range batch.Events {
				assert.Equal(t, "topic_1", e.Topic)
				// messages are published 0,1,2 over 10 topics, and we're only getting one of those topics
				expectedNumber += 10
			}
		})
	}

	// Check we ran the loop just once, and from the empty string for the checkpoint (as there was no InitialSequenceID)
	done()
	assert.Equal(t, "", ts.sequenceStartedWith)
	assert.Equal(t, 1, ts.startCount)
}

func TestE2E_WebsocketDeliveryRestartReset(t *testing.T) {
	ctx, p, wss, wsc, done := setupE2ETest(t)
	defer done()

	ts := &testSource{started: make(chan struct{})}
	close(ts.started) // start delivery immediately - will block as no WS connected

	mgr, err := NewEventStreamManager[testESConfig, testData](ctx, GenerateConfig(ctx), p, wss, ts)
	assert.NoError(t, err)

	// Create a stream to sub-select one topic
	es1 := &EventStreamSpec[testESConfig]{
		Name:        ptrTo("stream1"),
		TopicFilter: ptrTo("topic_1"), // only one of the topics
		Type:        &EventStreamTypeWebSocket,
		BatchSize:   ptrTo(10),
	}
	created, err := mgr.UpsertStream(ctx, es1)
	assert.NoError(t, err)
	assert.True(t, created)

	// Connect our websocket and start it
	err = wsc.Connect()
	assert.NoError(t, err)
	err = wsc.Send(ctx, []byte(`{"type":"start","stream":"stream1"}`))
	assert.NoError(t, err)

	// Get the first batch
	wsReceiveAck(ctx, t, wsc, func(batch *EventBatch[testData]) {})
	assert.Equal(t, "", ts.sequenceStartedWith)
	assert.Equal(t, 1, ts.startCount)

	// Wait for the checkpoint to be reflected in the status
	var ess *EventStreamWithStatus[testESConfig]
	for ess == nil || ess.Statistics == nil || ess.Statistics.Checkpoint == "" {
		time.Sleep(1 * time.Millisecond)
		ess, err = mgr.GetStreamByID(ctx, es1.ID)
		assert.NoError(t, err)
	}

	// Restart and check we get called with the checkpoint - note we don't reconnect the
	// websocket or restart that - it remains "started" from the websocket protocol
	// perspective throughout
	err = mgr.StopStream(ctx, es1.ID)
	assert.NoError(t, err)
	err = mgr.StartStream(ctx, es1.ID)
	assert.NoError(t, err)
	wsReceiveAck(ctx, t, wsc, func(batch *EventBatch[testData]) {})
	assert.Equal(t, "000000000009", ts.sequenceStartedWith)
	assert.Equal(t, 2, ts.startCount)

	// Reset it and check we get the reset
	err = mgr.ResetStream(ctx, es1.ID, "first")
	assert.NoError(t, err)
	wsReceiveAck(ctx, t, wsc, func(batch *EventBatch[testData]) {})
	assert.Equal(t, "first", ts.sequenceStartedWith)
	assert.Equal(t, 3, ts.startCount)

}

func TestE2E_DeliveryWebHooks200(t *testing.T) {
	ctx, p, wss, wsc, done := setupE2ETest(t)
	defer done()

	ts := &testSource{started: make(chan struct{})}
	close(ts.started) // start delivery immediately - will block as no WS connected

	mgr, err := NewEventStreamManager[testESConfig, testData](ctx, GenerateConfig(ctx), p, wss, ts)
	assert.NoError(t, err)

	got100 := make(chan struct{})
	var received int64
	expectedNumber := 1
	whServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		assert.Equal(t, http.MethodPut, req.Method)
		assert.Equal(t, "/some/path", req.URL.Path)
		assert.Equal(t, "my-value", req.Header.Get("My-Header"))

		var batch EventBatch[testData]
		err := json.NewDecoder(req.Body).Decode(&batch)
		assert.NoError(t, err)

		// each batch should be 10
		assert.Len(t, batch.Events, 10)
		for _, e := range batch.Events {
			assert.Equal(t, "topic_1", e.Topic)
			// messages are published 0,1,2 over 10 topics, and we're only getting one of those topics
			expectedNumber += 10
		}
		if (atomic.AddInt64(&received, 1)) == 100 {
			close(got100)
		}

		res.WriteHeader(200)
	}))
	defer whServer.Close()

	// Create a stream to sub-select one topic
	es1 := &EventStreamSpec[testESConfig]{
		Name:        ptrTo("stream1"),
		TopicFilter: ptrTo("topic_1"), // only one of the topics
		Type:        &EventStreamTypeWebhook,
		BatchSize:   ptrTo(10),
		Webhook: &WebhookConfig{
			URL:    ptrTo(whServer.URL + "/some/path"),
			Method: ptrTo("PUT"),
			Headers: map[string]string{
				"my-header": "my-value",
			},
		},
	}
	created, err := mgr.UpsertStream(ctx, es1)
	assert.NoError(t, err)
	assert.True(t, created)

	// Connect our websocket and start it
	err = wsc.Connect()
	assert.NoError(t, err)
	err = wsc.Send(ctx, []byte(`{"type":"start","stream":"stream1"}`))
	assert.NoError(t, err)

	// Check we ran the loop just once, and from the empty string for the checkpoint (as there was no InitialSequenceID)
	<-got100
	assert.Equal(t, "", ts.sequenceStartedWith)
	assert.Equal(t, 1, ts.startCount)
}

// This test demonstrates the CRUD features
func TestE2E_CRUDLifecycle(t *testing.T) {
	ctx, p, wss, _, done := setupE2ETest(t)
	defer done()

	ts := &testSource{
		started: make(chan struct{}), // we never start it
	}

	mgr, err := NewEventStreamManager[testESConfig, testData](ctx, GenerateConfig(ctx), p, wss, ts)
	assert.NoError(t, err)

	// Create first event stream started
	es1 := &EventStreamSpec[testESConfig]{
		Name:        ptrTo("stream1"),
		TopicFilter: ptrTo("topic1"), // only one of the topics
		Type:        &EventStreamTypeWebSocket,
		Config: &testESConfig{
			Config1: "confValue1",
		},
	}
	created, err := mgr.UpsertStream(ctx, es1)
	assert.NoError(t, err)
	assert.True(t, created)

	// Create second event stream stopped
	es2 := &EventStreamSpec[testESConfig]{
		Name:        ptrTo("stream2"),
		TopicFilter: ptrTo("topic2"), // only one of the topics
		Type:        &EventStreamTypeWebSocket,
		Status:      &EventStreamStatusStopped,
		Config: &testESConfig{
			Config1: "confValue2",
		},
	}
	created, err = mgr.UpsertStream(ctx, es2)
	assert.NoError(t, err)
	assert.True(t, created)

	// Find the second one by topic filter
	esList, _, err := mgr.ListStreams(ctx, EventStreamFilters.NewFilter(ctx).Eq("topicfilter", "topic2"))
	assert.NoError(t, err)
	assert.Len(t, esList, 1)
	assert.Equal(t, "stream2", *esList[0].Name)
	assert.Equal(t, "topic2", *esList[0].TopicFilter)
	assert.Equal(t, 50, *esList[0].BatchSize) // picked up default when it was loaded
	assert.Equal(t, "confValue2", esList[0].Config.Config1)
	assert.Equal(t, EventStreamStatusStopped, esList[0].Status)

	// Get the first by ID
	es1c, err := mgr.GetStreamByID(ctx, es1.ID, dbsql.FailIfNotFound)
	assert.NoError(t, err)
	assert.Equal(t, "stream1", *es1c.Name)
	assert.Equal(t, EventStreamStatusStarted, es1c.Status)

	// Start and re-stop, then delete the second event stream
	err = mgr.StartStream(ctx, es2.ID)
	assert.NoError(t, err)
	es2c, err := mgr.GetStreamByID(ctx, es2.ID, dbsql.FailIfNotFound)
	assert.NoError(t, err)
	assert.Equal(t, EventStreamStatusStarted, es2c.Status)
	err = mgr.StopStream(ctx, es2.ID)
	assert.NoError(t, err)
	es2c, err = mgr.GetStreamByID(ctx, es2.ID, dbsql.FailIfNotFound)
	assert.NoError(t, err)
	assert.Equal(t, EventStreamStatusStopped, es2c.Status)
	err = mgr.DeleteStream(ctx, es2.ID)
	assert.NoError(t, err)

	// Delete the first stream (which is running still)
	err = mgr.DeleteStream(ctx, es1.ID)
	assert.NoError(t, err)

	// Check no streams left
	esList, _, err = mgr.ListStreams(ctx, EventStreamFilters.NewFilter(ctx).And())
	assert.NoError(t, err)
	assert.Empty(t, esList)

}

func wsReceiveAck(ctx context.Context, t *testing.T, wsc wsclient.WSClient, cb func(batch *EventBatch[testData])) {
	data := <-wsc.Receive()
	var batch EventBatch[testData]
	err := json.Unmarshal(data, &batch)
	assert.NoError(t, err)
	cb(&batch)
	err = wsc.Send(ctx, []byte(fmt.Sprintf(`{"type":"ack","stream":"stream1","batchNumber":%d}`, batch.BatchNumber)))
	assert.NoError(t, err)
}

func setupE2ETest(t *testing.T, extraSetup ...func()) (context.Context, Persistence[testESConfig], wsserver.WebSocketChannels, wsclient.WSClient, func()) {
	logrus.SetLevel(logrus.TraceLevel)

	ctx := context.Background()
	config.RootConfigReset()
	conf := config.RootSection("ut")
	dbConf := conf.SubSection("db")
	esConf := conf.SubSection("eventstreams")
	dbsql.InitSQLiteConfig(dbConf)
	InitConfig(esConf)

	dbConf.Set(dbsql.SQLConfMigrationsAuto, true)
	dbConf.Set(dbsql.SQLConfDatasourceURL, "file::memory:")
	dbConf.Set(dbsql.SQLConfMigrationsAuto, true)
	dbConf.Set(dbsql.SQLConfMigrationsDirectory, "../../test/es_demo_migrations")
	dbConf.Set(dbsql.SQLConfMaxConnections, 1)

	for _, fn := range extraSetup {
		fn()
	}

	db, err := dbsql.NewSQLiteProvider(ctx, dbConf)
	assert.NoError(t, err)

	p := NewEventStreamPersistence[testESConfig](db)
	p.EventStreams().Validate()
	p.Checkpoints().Validate()

	wss := wsserver.NewWebSocketServer(ctx)
	server := httptest.NewServer(http.HandlerFunc(wss.Handler))

	// Build the WS connection, but don't connect it yet
	wsc, err := wsclient.New(ctx, &wsclient.WSConfig{
		HTTPURL: server.URL,
	}, nil, nil)

	return ctx, p, wss, wsc, func() {
		server.Close()
		wsc.Close()
	}

}
