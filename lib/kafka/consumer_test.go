package kafka_test

// type MockedKafkaError struct {
// 	mock.Mock
// }

// func (mke *MockedKafkaError) IsTimeout() bool {
// 	args := mke.Called()
// 	return args.Bool(0)
// }

// func (mke *MockedKafkaError) Error() string {
// 	args := mke.Called()
// 	return args.String(0)
// }

// type MockedKafkaConsumer struct {
// 	mock.Mock
// }

// func (mkc *MockedKafkaConsumer) Close() error {
// 	args := mkc.Called()
// 	return args.Error(0)
// }

// func (mkc *MockedKafkaConsumer) SubscribeTopics(topics []string, rebalanceCb kafka.RebalanceCb) error {
// 	args := mkc.Called(topics, rebalanceCb)
// 	return args.Error(0)
// }

// func (mkc *MockedKafkaConsumer) ReadMessage(timeout time.Duration) (*kafka.Message, error) {
// 	args := mkc.Called(timeout)

// 	if args.Get(0) == nil {
// 		return nil, args.Error(1)
// 	}

// 	return args.Get(0).(*kafka.Message), args.Error(1)
// }

// type MockedProcessHandler struct {
// 	mock.Mock
// }

// func (mph *MockedProcessHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
// 	args := mph.Called(msg, storage)
// 	return args.Error(0)
// }

// type MockedStorageHandler struct {
// 	mock.Mock
// }

// func (msh *MockedStorageHandler) Store(msg interface{}) error {
// 	args := msh.Called(msg)
// 	return args.Error(0)
// }

// func (msh *MockedStorageHandler) Close() error {
// 	args := msh.Called()
// 	return args.Error(0)
// }

// func (msh *MockedStorageHandler) Open() error {
// 	args := msh.Called()
// 	return args.Error(0)
// }

// func TestKafkaEventConsumer_Consume(t *testing.T) {
// 	disableLog()

// 	t.Run("valid consume", func(t *testing.T) {
// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: &consumer.EmptyProcessHandler{},
// 		}

// 		err := wrapConsume(kc.Consume)
// 		assert.Nil(t, err, "expected no error")

// 		kc.Close()
// 	})

// 	t.Run("nil consumer", func(t *testing.T) {
// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       nil,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: &consumer.EmptyProcessHandler{},
// 		}

// 		err := kc.Consume(context.Background(), "test")
// 		assert.NotNil(t, err, "expected error on nil consumer")
// 	})

// 	t.Run("nil storage", func(t *testing.T) {
// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       &MockedKafkaConsumer{},
// 			StorageHandler: nil,
// 			ProcessHandler: &consumer.EmptyProcessHandler{},
// 		}

// 		err := kc.Consume(context.Background(), "test")
// 		assert.NotNil(t, err, "expected error on nil storage")
// 	})

// 	t.Run("failed open storage", func(t *testing.T) {
// 		mkc := &MockedKafkaConsumer{}

// 		msh := &MockedStorageHandler{}
// 		msh.On("Open").Return(errors.New("failed to open storage"))
// 		msh.On("Close").Return(nil)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: msh,
// 			ProcessHandler: &consumer.EmptyProcessHandler{},
// 		}

// 		err := kc.Consume(context.Background(), "test")
// 		assert.NotNil(t, err, "expected error on open storage")
// 	})

// 	t.Run("continue on process error", func(t *testing.T) {
// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

// 		mph := &MockedProcessHandler{}
// 		mph.On("Process", mock.Anything, mock.Anything).Return(errors.New("failed to process"))

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: mph,
// 		}

// 		err := wrapConsume(kc.Consume)
// 		assert.Nil(t, err, "expect to continue on process error")
// 	})

// 	t.Run("ignore consumer nil on close", func(t *testing.T) {
// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       nil,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: &consumer.EmptyProcessHandler{},
// 		}

// 		err := kc.Close()
// 		assert.Nil(t, err, "expected no error on nil consumer")
// 	})

// 	t.Run("failed subscribe", func(t *testing.T) {
// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(io.EOF)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: &consumer.EmptyProcessHandler{},
// 		}

// 		err := wrapConsume(kc.Consume)
// 		assert.NotNil(t, err, "expected error on subscribe")
// 	})

// 	t.Run("timeout readmessage", func(t *testing.T) {
// 		mke := &MockedKafkaError{}
// 		mke.On("IsTimeout").Return(false)
// 		mke.On("Error").Return("timeout")

// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, mke)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: &consumer.EmptyProcessHandler{},
// 		}

// 		err := wrapConsume(kc.Consume)
// 		assert.NotNil(t, err, "should stop consuming")
// 	})

// 	t.Run("continue on timeout", func(t *testing.T) {
// 		mke := &MockedKafkaError{}
// 		mke.On("IsTimeout").Return(true)
// 		mke.On("Error").Return("timeout")

// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, mke)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: &consumer.EmptyProcessHandler{},
// 		}

// 		err := wrapConsume(kc.Consume)
// 		assert.Nil(t, err, "expected only timeout error which should be skipped")
// 	})

// 	t.Run("failed read", func(t *testing.T) {
// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(nil, io.EOF)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: &consumer.EmptyProcessHandler{},
// 		}

// 		err := wrapConsume(kc.Consume)
// 		assert.NotNil(t, err, "expected error on EOF read")
// 	})
// }

// func TestKafkaEventConsumer_NewConsumer(t *testing.T) {
// 	disableLog()

// 	t.Run("valid consumer on empty config", func(t *testing.T) {
// 		kc, err := consumer.NewKafkaEventConsumer(nil, &consumer.EmptyProcessHandler{}, &storage.EmptyStorageHandler{})
// 		assert.Nil(t, err, "expected valid consumer with default settings")
// 		require.NotNil(t, kc, "expected valid kafka consumer")
// 	})

// 	t.Run("no process handler", func(t *testing.T) {
// 		kc, err := consumer.NewKafkaEventConsumer(nil, nil, &storage.EmptyStorageHandler{})
// 		assert.NotNil(t, err, "expected error on nil process handler")
// 		assert.Nil(t, kc, "expected nil consumer on error")
// 	})

// 	t.Run("no storage handler", func(t *testing.T) {
// 		kc, err := consumer.NewKafkaEventConsumer(nil, &consumer.EmptyProcessHandler{}, nil)
// 		assert.NotNil(t, err, "expected error on nil storage handler")
// 		assert.Nil(t, kc, "expected nil consumer on error")
// 	})

// 	t.Run("vaild on empty handlers", func(t *testing.T) {
// 		config := &consumer.KafkaConsumerConfig{
// 			Server:        "localhost:9092",
// 			ConsumerGroup: "test",
// 		}

// 		kc, err := consumer.NewKafkaEventConsumer(config, &consumer.EmptyProcessHandler{}, &storage.EmptyStorageHandler{})
// 		assert.Nil(t, err, "expected no error on empty handlers")
// 		assert.NotNil(t, kc, "expected valid consumer")
// 	})

// 	t.Run("no error on missing server in config", func(t *testing.T) {
// 		config := &consumer.KafkaConsumerConfig{
// 			ConsumerGroup: "test",
// 		}

// 		kc, err := consumer.NewKafkaEventConsumer(config, &consumer.EmptyProcessHandler{}, &storage.EmptyStorageHandler{})
// 		assert.Nil(t, err, "expected default values on missing server in config")
// 		assert.NotNil(t, kc, "expected non nil consumer")
// 	})

// 	t.Run("error on missing consumer group in config", func(t *testing.T) {
// 		config := &consumer.KafkaConsumerConfig{
// 			Server: "localhost:9092",
// 		}

// 		kc, err := consumer.NewKafkaEventConsumer(config, &consumer.EmptyProcessHandler{}, &storage.EmptyStorageHandler{})
// 		assert.Nil(t, err, "expected default values on missing consumer group")
// 		assert.NotNil(t, kc, "expected nil consumer on error")
// 	})
// }

// func disableLog() {
// 	logrus.SetOutput(io.Discard)
// }

// func wrapConsume(consume func(context context.Context, topic string) error) error {
// 	ctx, cancel := context.WithCancel(context.Background())

// 	wg := sync.WaitGroup{}
// 	wg.Add(1)

// 	var err error

// 	go func() {
// 		err = consume(ctx, "test")
// 		defer wg.Done()
// 	}()

// 	time.Sleep(100 * time.Millisecond)

// 	cancel()
// 	wg.Wait()
// 	return err
// }
