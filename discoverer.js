const threadIds = new Set();
const result = new Map();

rpc.exports = {
  start: function () {
    for (const { id: threadId } of Process.enumerateThreads()) {
      threadIds.add(threadId);
      Stalker.follow(threadId, {
        events: { call: true },
        onCallSummary(summary) {
          for (const [address, count] of Object.entries(summary)) {
            result.set(address, (result.get(address) ?? 0) + count);
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

    const moduleMap = new ModuleMap();
    const allModules = moduleMap
      .values()
      .reduce((m, module) => m.set(module.path, module), new Map());
    const moduleDetails = new Map();
    let nextModuleId = 1;

    for (const [address, count] of result.entries()) {
      let moduleId = 0;
      let name;
      let visibility = "i";
      const addressPtr = ptr(address);

      const path = moduleMap.findPath(addressPtr);
      if (path !== null) {
        const module = allModules.get(path);

        let details = moduleDetails.get(path);
        if (details !== undefined) {
          moduleId = details.id;
        } else {
          moduleId = nextModuleId++;

          details = {
            id: moduleId,
            exports: module
              .enumerateExports()
              .reduce((m, e) => m.set(e.address.toString(), e.name), new Map()),
          };
          moduleDetails.set(path, details);

          modules[moduleId] = module;
        }

        const exportName = details.exports.get(address);
        if (exportName !== undefined) {
          name = exportName;
          visibility = "e";
        } else {
          name = "sub_" + addressPtr.sub(module.base).toString(16);
        }
      } else {
        name = "dsub_" + addressPtr.toString(16);
      }

      targets.push([moduleId, name, visibility, address, count]);
    }

    result.clear();

    return {
      targets,
      modules,
    };
  },
};
