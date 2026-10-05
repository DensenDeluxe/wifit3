from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Union

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select, TextArea

from wifit3.campaigns.csa_decloak import (
    CsaDecloakInput, csa_default_dest, csa_dest_channels,
)
from wifit3.campaigns.decloak import SIBLING_SUFFIXES, expand_candidates
from wifit3.chips.driver import FakeMacSupport
from wifit3.persist.config import Config
from wifit3.ui.path_picker import PathPickerModal
from wifit3.ui.screens.focus_v2.art import display_name
from wifit3.wlan.array import fake_mac_rank

_WORDLIST_CAP = 500

DecloakRequest = Union[List[str], CsaDecloakInput]


class DecloakModal(ModalScreen[Optional[DecloakRequest]]):
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    DEFAULT_CSS = """
    DecloakModal { align: center middle; }
    DecloakModal #dialog {
        width: 64; height: auto; max-height: 90%;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    DecloakModal #title { width: 1fr; content-align: center middle; margin-bottom: 1; text-style: bold; }
    DecloakModal #mode { margin-bottom: 1; }
    DecloakModal .row { height: auto; margin-bottom: 1; }
    DecloakModal .row-label { width: 12; height: 3; content-align: left middle; color: $text-muted; }
    DecloakModal .row Input, DecloakModal .row Select { width: 1fr; }
    DecloakModal #hint, DecloakModal #csa-note { color: $text-muted; height: auto; }
    DecloakModal #candidates { height: 12; border: round $primary; margin-bottom: 1; }
    DecloakModal #csa-form { height: auto; }
    DecloakModal #csa-fakeap { border: none; height: 1; padding: 0 1; margin-bottom: 1;
                               background: transparent; }
    DecloakModal #warn { color: $text-warning; height: auto; display: none; }
    DecloakModal #button-row { height: auto; align: center middle; }
    DecloakModal #button-row Button { margin: 0 1; }
    """

    def __init__(self, target, base_ssid: str = "", members: Optional[List] = None) -> None:
        super().__init__()
        self.target = target
        self.base_ssid = base_ssid
        self._members = list(members or [])
        self._by_name = {m.name: m for m in self._members}
        sender_available = any(target.channel in getattr(m, "supported_channels", [])
                               for m in self._members)
        listener_available = any(csa_dest_channels(target.channel,
                                                   getattr(m, "supported_channels", []))
                                 for m in self._members)
        self._csa_available = (bool(getattr(target, "last_beacon_frame", None))
                               and sender_available and listener_available)

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(f"Decloak hidden AP  [dim]{self.target.bssid}[/dim]", id="title")
            mode_opts = [("Directed probe (wordlist)", "probe")]
            if self._csa_available:
                mode_opts.append(("CSA: evict clients (no wordlist)", "csa"))
            yield Select(mode_opts, value="probe", allow_blank=False, id="mode")

            with Vertical(id="probe-form"):
                with Horizontal(classes="row"):
                    yield Label("$ssid base", classes="row-label")
                    yield Input(value=self.base_ssid,
                                placeholder="visible sibling SSID, or type one", id="base")
                yield Label("One SSID per line. [b]$ssid[/b] expands to the base above.", id="hint")
                yield TextArea(self._initial_text(), id="candidates", show_line_numbers=False)

            if self._csa_available:
                listener = self._default_listener()
                with Vertical(id="csa-form"):
                    with Horizontal(classes="row"):
                        yield Label("Sender card", classes="row-label")
                        yield Select(self._iface_options(),
                                     value=self._iface_name(self._default_sender()),
                                     allow_blank=False, id="csa-sender")
                    with Horizontal(classes="row"):
                        yield Label("Listener card", classes="row-label")
                        yield Select(self._iface_options(), value=self._iface_name(listener),
                                     allow_blank=False, id="csa-listener")
                    with Horizontal(classes="row"):
                        yield Label("Dest channel", classes="row-label")
                        yield Select(self._dest_options(listener), prompt="No supported channel",
                                     value=self._dest_default(listener), allow_blank=True,
                                     id="csa-dest")
                    yield Checkbox("Decoy AP on dest (answer Auth/Assoc)", value=True,
                                   id="csa-fakeap")
                    yield Label("CSA herds the AP's clients to another channel; a returning client "
                                "names the hidden SSID. Best with two cards.", id="csa-note")

            yield Label("", id="warn")
            with Horizontal(id="button-row"):
                yield Button("Load wordlist…", id="btn-load")
                yield Button("Decloak", variant="primary", id="btn-go")
                yield Button("Cancel", variant="default", id="btn-cancel")

    def on_mount(self) -> None:
        self._apply_mode("probe")
        if self._csa_available:
            self._sync_fakeap_enabled()

    def _initial_text(self) -> str:
        suffixes = SIBLING_SUFFIXES if self.base_ssid else ("", "-Guest", "-5G", "-IoT")
        return "\n".join(f"$ssid{suffix}" for suffix in suffixes
                         if not self.base_ssid
                         or len(f"{self.base_ssid}{suffix}".encode("utf-8")) <= 32)

    def _iface_options(self) -> List:
        return [(display_name(m), m.name) for m in self._members]

    @staticmethod
    def _iface_name(iface):
        return iface.name if iface is not None else Select.BLANK

    def _default_sender(self):
        ranked = sorted(
            (m for m in self._members
             if self.target.channel in getattr(m, "supported_channels", [])),
            key=fake_mac_rank,
        )
        return ranked[0] if ranked else None

    def _default_listener(self):
        sender = self._default_sender()
        capable = [m for m in self._members
                   if csa_dest_channels(self.target.channel,
                                        getattr(m, "supported_channels", []))]
        return next((m for m in capable if m is not sender), capable[0] if capable else None)

    def _selected(self, widget_id: str):
        return self._by_name.get(self.query_one(f"#{widget_id}", Select).value)

    def _dest_options(self, listener) -> List:
        supported = listener.supported_channels if listener is not None else []
        return [(str(c), c) for c in csa_dest_channels(self.target.channel, supported)]

    def _dest_default(self, listener):
        options = [c for _, c in self._dest_options(listener)]
        return csa_default_dest(self.target.channel, options) or Select.BLANK

    @staticmethod
    def _listener_can_host(listener) -> bool:
        return getattr(getattr(listener, "driver", None), "FAKE_MAC", None) is FakeMacSupport.SPOOFABLE

    def _apply_mode(self, mode: str) -> None:
        csa = mode == "csa"
        self.query_one("#probe-form").display = not csa
        self.query_one("#btn-load").display = not csa
        if self._csa_available:
            self.query_one("#csa-form").display = csa
        self._sync_warn()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "mode":
            self._apply_mode(event.value)
        elif event.select.id == "csa-listener":
            dest = self.query_one("#csa-dest", Select)
            listener = self._selected("csa-listener")
            dest.set_options(self._dest_options(listener))
            dest.value = self._dest_default(listener)
            self._sync_fakeap_enabled()
            self._sync_warn()
        elif event.select.id == "csa-sender":
            self._sync_fakeap_enabled()
            self._sync_warn()

    def _sync_fakeap_enabled(self) -> None:
        checkbox = self.query_one("#csa-fakeap", Checkbox)
        sender, listener = self._selected("csa-sender"), self._selected("csa-listener")
        two_cards = sender is not None and listener is not None and sender is not listener
        ok = two_cards and self._listener_can_host(listener)
        checkbox.disabled = not ok
        if ok:
            checkbox.tooltip = "Answer Auth/Assoc so an evicted client's Assoc Request names the SSID"
        else:
            checkbox.value = False
            checkbox.tooltip = ("Needs two different cards" if not two_cards
                                else "Listener card can't spoof the AP's BSSID")

    def _sync_warn(self) -> None:
        if self._csa_available and self.query_one("#mode", Select).value == "csa":
            sender, listener = self._selected("csa-sender"), self._selected("csa-listener")
            if not self._dest_options(listener):
                self._set_warn("Listener card has no supported in-band destination channel")
            else:
                self._set_warn("One card: CSA send + listen are time-sliced (best with two cards)"
                               if sender is listener else "")
        else:
            self._set_warn("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-go":
            self._submit()
        elif bid == "btn-load":
            self._load_wordlist()
        elif bid == "btn-cancel":
            self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _submit(self) -> None:
        if self._csa_available and self.query_one("#mode", Select).value == "csa":
            self._submit_csa()
        else:
            self._submit_probe()

    def _submit_probe(self) -> None:
        base = self.query_one("#base", Input).value
        lines = self.query_one("#candidates", TextArea).text.splitlines()
        try:
            candidates = expand_candidates(lines, base, max_candidates=_WORDLIST_CAP)
        except ValueError as exc:
            self._error(str(exc))
            return
        if not candidates:
            self._error("Enter at least one candidate SSID")
            return
        self.dismiss(candidates)

    def _submit_csa(self) -> None:
        sender = self._selected("csa-sender")
        listener = self._selected("csa-listener")
        dest = self.query_one("#csa-dest", Select).value
        if sender is None or listener is None or not isinstance(dest, int):
            self._error("Pick a sender card, a listener card and a destination channel")
            return
        if self.target.channel not in getattr(sender, "supported_channels", []):
            self._error(f"Sender card can't reach the AP's channel (CH {self.target.channel})")
            return
        if dest not in csa_dest_channels(self.target.channel,
                                         getattr(listener, "supported_channels", [])):
            self._error(f"Listener card can't reach destination channel CH {dest}")
            return
        self.dismiss(CsaDecloakInput(sender_iface=sender, listener_iface=listener, dest_channel=dest,
                                     stand_up_ap=self.query_one("#csa-fakeap", Checkbox).value))

    def _load_wordlist(self) -> None:
        start = Config.wordlist_path or str(Path.home())
        self.app.push_screen(PathPickerModal(start, title="Load SSID wordlist"),
                             self._wordlist_picked)

    def _wordlist_picked(self, path: Optional[Path]) -> None:
        if path is None:
            return
        area = self.query_one("#candidates", TextArea)
        base = self.query_one("#base", Input).value
        try:
            existing_candidates = expand_candidates(
                area.text.splitlines(), base, max_candidates=_WORDLIST_CAP
            )
        except ValueError as exc:
            self._error(str(exc))
            return
        if len(existing_candidates) >= _WORDLIST_CAP:
            self.notify(f"Candidate limit is {_WORDLIST_CAP}", severity="warning")
            return
        try:
            lines, truncated = self._read_wordlist_prefix(path, _WORDLIST_CAP)
        except OSError as exc:
            self.notify(f"Could not read {path}: {exc}", severity="error")
            return

        seen = set(existing_candidates)
        appended: List[str] = []
        for line in lines:
            try:
                expanded = expand_candidates([line], base)
            except ValueError as exc:
                self._error(f"{Path(path).name}: {exc}")
                return
            if not expanded or expanded[0] in seen:
                continue
            if len(seen) >= _WORDLIST_CAP:
                truncated = True
                break
            seen.add(expanded[0])
            appended.append(line)

        existing = area.text.rstrip("\n")
        if appended:
            area.load_text((existing + "\n" if existing else "") + "\n".join(appended))
        if truncated or len(seen) >= _WORDLIST_CAP:
            self.notify(f"Loaded {len(appended)} SSIDs; candidate limit is {_WORDLIST_CAP}",
                        severity="warning")
        else:
            self.notify(f"Loaded {len(appended)} SSIDs from {Path(path).name}")

    @staticmethod
    def _read_wordlist_prefix(path: Path, max_lines: int) -> tuple[List[str], bool]:
        lines: List[str] = []
        truncated = False
        with Path(path).open("r", encoding="utf-8", errors="replace") as source:
            for line_number, raw_line in enumerate(source, 1):
                if line_number > max_lines:
                    truncated = True
                    break
                line = raw_line.rstrip("\r\n")
                if line:
                    lines.append(line)
        return lines, truncated

    def _error(self, text: str) -> None:
        self._set_warn(f"[red]{text}[/red]")

    def _set_warn(self, text: str) -> None:
        warn = self.query_one("#warn", Label)
        warn.update(text)
        warn.display = bool(text)
