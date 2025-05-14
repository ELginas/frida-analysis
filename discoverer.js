const threadIds = new Set();
const functions = new Map();

function resultToJsonObj(result) {
  let obj = {};
  for (const [k, v] of result.entries()) {
    const location = k.toString(16);
    obj[location] = [];
    for (const target of v) {
      const hexTarget = target.toString(16);
      obj[location].push(hexTarget);
    }
  }
  return obj;
}

function moduleMapToJsonArray(moduleMap) {
  const array = [];
  const modules = moduleMap.values();
  for (const module of modules) {
    const entry = {};
    entry.name = module.name;
    entry.base = module.base;
    entry.size = module.size;
    entry.path = module.path;
    array.push(entry);
  }
  return array;
}

rpc.exports = {
  start: function () {
    for (const { id: threadId } of Process.enumerateThreads()) {
      threadIds.add(threadId);
      Stalker.follow(threadId, {
        events: { call: true },
        onReceive(events) {
          let dataview = new DataView(events);
          let cursor = 0;

          // Actually the format is:
          // Size: 32; align: 8
          // type: 0 (4)
          // _pad1: 4 (4)
          // location: 8 (8)
          // target: 16 (8)
          // depth: 24 (4)
          // _pad2: 28 (4)
          // _pad1 and _pad2 kinda leak memory, is random and shouldn't be read.
          while (cursor < dataview.byteLength) {
            const type = dataview.getUint32(cursor, true);
            cursor += 4;
            if (type == 1) {
              const location = dataview.getBigUint64(cursor + 4, true);
              const target = dataview.getBigUint64(cursor + 12, true);
              cursor += 28;

              if (!functions.has(location)) {
                functions.set(location, []);
              }
              const targets = functions.get(location);
              if (!targets.includes(target)) {
                targets.push(target);
              }
            } else {
              console.error("unknown type", type);
              console.error(dataview.buffer.slice(cursor, cursor + 16));
            }
          }
        },
      });
    }

    return {
      total: threadIds.size,
    };
  },
  stop: function () {
    for (const threadId of threadIds.values()) {
      Stalker.unfollow(threadId);
    }
    threadIds.clear();

    const moduleMap = new ModuleMap();
    const json = JSON.stringify({
      functions: resultToJsonObj(functions),
      modules: moduleMapToJsonArray(moduleMap),
    });

    return json;
  },
};
