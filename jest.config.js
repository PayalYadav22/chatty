export default {
  transform: {
    "^.+\\.js$": "babel-jest",
  },
  testEnvironment: "node",
  transformIgnorePatterns: ["/node_modules/(?!mongodb-memory-server)"],
  setupFilesAfterEnv: ["<rootDir>/src/tests/index.js"],
  globals: {
    "babel-jest": {
      useESM: true,
    },
  },
  moduleNameMapper: {
    "^utils/(.*)$": "<rootDir>/src/utils/$1",
    "^config/(.*)$": "<rootDir>/src/config/$1",
    "^models/(.*)$": "<rootDir>/src/models/$1",
    "^app/(.*)$": "<rootDir>/src/app/$1",
    "^log/(.*)$": "<rootDir>/src/utils/log/$1",
  },
};
