// middleware/errorMiddleware.js

const errorHandler = (err, req, res, next) => {
<<<<<<< HEAD
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(statusCode);
  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === "production" ? "🥞" : err.stack,
  });
};

module.exports = {
  errorHandler,
};
=======
    const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
    res.status(statusCode);
    res.json({
      message: err.message,
      stack: process.env.NODE_ENV === 'production' ? '🥞' : err.stack,
    });
  };
  
  module.exports = {
    errorHandler,
  };
  
>>>>>>> 83781368d03c081e7c5ffac8faddbe42901aa2a1
