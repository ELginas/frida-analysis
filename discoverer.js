const threadIds = new Set();
const result = new Map();

function resultToJSON(result) {
  let obj = {};
  for (const [k, v] of result.entries()) {
    const location = k.toString(16);
    obj[location] = [];
    for (const target of v) {
      const hexTarget = target.toString(16);
      obj[location].push(hexTarget);
    }
  }
  return JSON.stringify(obj);
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

              if (!result.has(location)) {
                result.set(location, []);
              }
              const targets = result.get(location);
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

    const targets = [];
    const modules = {};

    console.log(resultToJSON(result));

    return {
      targets,
      modules,
    };
  },
};
