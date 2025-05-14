import argparse
import sys
import threading
from typing import List, Optional

import frida

from frida_tools.application import ConsoleApplication, await_enter
from frida_tools.reactor import Reactor


class UI:

    def on_sample_start(self, total: int) -> None:
        pass

    def on_sample_result(self, result_json: str, module_map_json: str) -> None:
        pass

    def _on_script_created(self, script: frida.core.Script) -> None:
        pass


class Discoverer:

    def __init__(self, reactor: Reactor) -> None:
        self._reactor = reactor
        self._ui = None
        self._script: Optional[frida.core.Script] = None

    def dispose(self) -> None:
        if self._script is not None:
            try:
                self._script.unload()
            except:
                pass
            self._script = None

    def start(self, session: frida.core.Session, runtime: str, ui: UI) -> None:

        def on_message(message, data) -> None:
            print(message, data)

        self._ui = ui

        script = session.create_script(name="discoverer",
                                       source=self._create_discover_script(),
                                       runtime=runtime)
        self._script = script
        self._ui._on_script_created(script)
        script.on("message", on_message)
        script.load()

        params = script.exports_sync.start()
        ui.on_sample_start(params["total"])

    def stop(self) -> None:
        result = self._script.exports_sync.stop()

        self._ui.on_sample_result(result['resultJSON'],
                                  result['moduleMapJSON'])

    def _create_discover_script(self) -> str:
        return open("discoverer.js").read()


class DiscovererApplication(ConsoleApplication, UI):
    _discoverer: Optional[Discoverer]

    def __init__(self) -> None:
        self._results_received = threading.Event()
        ConsoleApplication.__init__(self, self._await_keys)

    def _await_keys(self, reactor: Reactor) -> None:
        await_enter(reactor)
        reactor.schedule(lambda: self._discoverer.stop())
        while reactor.is_running() and not self._results_received.is_set():
            self._results_received.wait(0.5)

    def _usage(self) -> str:
        return "%(prog)s [options] target"

    def _initialize(self, parser: argparse.ArgumentParser,
                    options: argparse.Namespace, args: List[str]) -> None:
        self._discoverer = None

    def _needs_target(self) -> bool:
        return True

    def _update_status(self, msg) -> None:
        print(msg, file=sys.stderr)

    def _start(self) -> None:
        self._update_status("Injecting script...")
        self._discoverer = Discoverer(self._reactor)
        self._discoverer.start(self._session, self._runtime, self)

    def _stop(self) -> None:
        self._update_status("Stopping...")
        assert self._discoverer is not None
        self._discoverer.dispose()
        self._discoverer = None

    def on_sample_start(self, total: int) -> None:
        self._update_status(f"Tracing {total} threads. Press ENTER to stop.")
        self._resume()

    def on_sample_result(self, result_json: str, module_map_json: str) -> None:
        print(result_json)
        print(module_map_json)

        self._results_received.set()


def main() -> None:
    app = DiscovererApplication()
    app.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
