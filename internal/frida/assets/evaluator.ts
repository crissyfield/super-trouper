// Evaluates the JavaScript statement given in the request and reports its JSON result.
function receiveEvaluation() {
  recv('evaluate', function(message) {
    const { id, source } = message.payload;

    try {
      // Evaluate and report result
      send({ id, result: (0, eval)(source) });
    } catch (error) {
      // Report JavaScript error
      send({
        id,
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack
        }
      });
    }

    receiveEvaluation();
  });
}

// Reads the requested number of bytes at the given address and reports them as the response's binary payload.
function receiveMemoryRead() {
  recv('memory_read', function(message) {
    const { id, address, count } = message.payload;

    try {
      // Read memory and report as binary payload
      send({ id }, ptr(address).readByteArray(count));
    } catch (error) {
      // Report JavaScript error
      send({
        id,
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack
        }
      });
    }

    receiveMemoryRead();
  });
}

// Writes the request's binary payload at the given address and reports the number of bytes written.
function receiveMemoryWrite() {
  recv('memory_write', function(message) {
    const { id, address } = message.payload;

    try {
      // Write memory and report number of bytes written
      if (!message.data) {
        throw new Error('missing binary payload');
      }

      const bytes = new Uint8Array(message.data);
      ptr(address).writeByteArray(bytes);

      send({ id, result: bytes.length });
    } catch (error) {
      // Report JavaScript error
      send({
        id,
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack
        }
      });
    }

    receiveMemoryWrite();
  });
}

// Start listening for requests
receiveEvaluation();
receiveMemoryRead();
receiveMemoryWrite();
