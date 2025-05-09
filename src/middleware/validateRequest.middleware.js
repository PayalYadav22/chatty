const validateRequest = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body, { abortEarly: false });
    if (error) {
      const details = error.details.map((d) => d.message).join(", ");
      return res.status(400).json({
        status: "error",
        message: `Validation error: ${details}`,
      });
    }

    next();
  };
};

export default validateRequest;
