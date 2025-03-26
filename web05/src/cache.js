const cache = {};

function addResultsToCache(id, results) {
  cache[id] = results;
}

function getResultsFromCache(id) {
  return cache[id];
}

module.exports = {
  addResultsToCache,
  getResultsFromCache
};
