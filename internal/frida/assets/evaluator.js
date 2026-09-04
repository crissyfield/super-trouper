function receiveEvaluation() {
  recv('evaluate', function (message) {
    const { id, source } = message.payload;

    try {
      send({ id, result: (0, eval)(source) });
    } catch (error) {
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

receiveEvaluation();
