"""LocalVault - offline Windows password container, 3-tab user interface."""
from __future__ import annotations

import os
import hashlib
import hmac
import secrets
import sys
import time
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from securebox_core import (
    VaultError, atomic_write, decrypt_secret, disguise_as_zip,
    encrypt_secret, generate_password, read_encrypted_file,
)
from windows_vault import WindowsVault

BG = "#0c0d10"
PANEL = "#15171c"
PANEL2 = "#1e2128"
FG = "#f0f1f3"
MUTED = "#a4a9b4"
ACCENT = "#d8dce6"
BORDER = "#363b46"


class LocalVaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Arquivo Local")
        self.geometry("960x735")
        self.minsize(800, 670)
        self.configure(bg=BG)
        self.vault = None
        self.vault_error = ""
        try:
            self.vault = WindowsVault()
        except Exception as exc:
            self.vault_error = str(exc)
        self.source_file: Path | None = None
        self.source_id: str | None = None
        self.disguise_file: Path | None = None
        self.recovered_password = tk.StringVar()
        self.recovered_label = tk.StringVar()
        self.clipboard_digest: bytes | None = None
        self.failed_attempts = 0
        self.next_unlock_time = 0.0
        self._idle_timer = None
        self._reveal_timer = None
        self._clipboard_timer = None
        self._scroll_canvases = {}
        self._configure_styles()
        self._render()
        self.bind_all("<KeyPress>", self._touch, add="+")
        self.bind_all("<ButtonPress>", self._touch, add="+")
        self.bind_all("<MouseWheel>", self._wheel, add="+")
        self.bind_all("<Control-l>", lambda _e: self._lock(), add="+")
        self.tabs.bind("<<NotebookTabChanged>>", self._on_tab_changed, add="+")
        self._touch()
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_styles(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("TFrame", background=BG)
        st.configure("Panel.TFrame", background=PANEL)
        st.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        st.configure("Panel.TLabel", background=PANEL, foreground=FG, font=("Segoe UI", 10))
        st.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        st.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 9))
        st.configure("Title.TLabel", background=BG, foreground=FG, font=("Segoe UI Semibold", 22))
        st.configure("Section.TLabel", background=PANEL, foreground=FG, font=("Segoe UI Semibold", 12))
        st.configure("TEntry", fieldbackground=PANEL2, foreground=FG, insertcolor=FG,
                     bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, padding=10)
        st.map("TEntry", fieldbackground=[("readonly", PANEL2)])
        st.configure("TButton", background=PANEL2, foreground=FG, relief="flat", borderwidth=0,
                     padding=(14, 10), font=("Segoe UI Semibold", 9))
        st.map("TButton", background=[("active", BORDER), ("pressed", BORDER)])
        st.configure("Accent.TButton", background=ACCENT, foreground="#15161a", padding=(18, 11))
        st.map("Accent.TButton", background=[("active", "#fafafa"), ("pressed", "#c4c7ce")])
        st.configure("TCheckbutton", background=PANEL, foreground=FG,
                     font=("Segoe UI", 9))
        st.map("TCheckbutton", background=[("active", PANEL)], foreground=[("active", FG)])
        st.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 3, 0, 0))
        st.configure("TNotebook.Tab", background=PANEL, foreground=MUTED, padding=(23, 12),
                     font=("Segoe UI Semibold", 10), borderwidth=0)
        st.map("TNotebook.Tab", background=[("selected", PANEL2)], foreground=[("selected", FG)])

    def _label(self, parent, text, muted=False):
        return ttk.Label(parent, text=text, style="PanelMuted.TLabel" if muted else "Panel.TLabel")

    def _panel(self, parent, title: str):
        frame = ttk.Frame(parent, style="Panel.TFrame", padding=(21, 18))
        ttk.Label(frame, text=title, style="Section.TLabel").pack(anchor="w", pady=(0, 5))
        return frame

    def _field(self, parent, title, text_var, *, masked=False):
        self._label(parent, title).pack(anchor="w", pady=(13, 5))
        entry = ttk.Entry(parent, textvariable=text_var, show="●" if masked else "")
        entry.pack(fill="x")
        return entry

    def _scroll_body(self, tab):
        wrapper = ttk.Frame(tab)
        wrapper.pack(fill="both", expand=True)
        canvas = tk.Canvas(wrapper, background=BG, borderwidth=0, highlightthickness=0)
        bar = ttk.Scrollbar(wrapper, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body = ttk.Frame(canvas, padding=(5, 13))
        window_id = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window_id, width=event.width))
        body.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        self._scroll_canvases[str(tab)] = canvas
        return body

    def _wheel(self, event):
        if isinstance(event.widget, tk.Listbox):
            return
        canvas = self._scroll_canvases.get(self.tabs.select())
        if canvas is not None:
            canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

    def _render(self):
        header = ttk.Frame(self, padding=(25, 19, 25, 5))
        header.pack(fill="x")
        ttk.Label(header, text="Arquivo Local", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Cofre de senhas offline  /  arquivos autenticados  /  proteção do Windows",
                  style="Muted.TLabel").pack(anchor="w", pady=(5, 0))
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=24, pady=(12, 10))
        create_outer = ttk.Frame(self.tabs)
        recover_outer = ttk.Frame(self.tabs)
        disguise_outer = ttk.Frame(self.tabs)
        self.create_tab = self._scroll_body(create_outer)
        self.recover_tab = self._scroll_body(recover_outer)
        self.disguise_tab = self._scroll_body(disguise_outer)
        self.tabs.add(create_outer, text="01  Criar e proteger")
        self.tabs.add(recover_outer, text="02  Recuperar")
        self.tabs.add(disguise_outer, text="03  Disfarçar arquivo")
        self._build_create()
        self._build_recover()
        self._build_disguise()
        ttk.Label(self, text="AES-256-GCM  •  Argon2id (256 MiB)  •  DPAPI (cofre Windows)  •  Sem internet",
                  style="Muted.TLabel").pack(anchor="w", padx=30, pady=(0, 13))

    def _build_create(self):
        pane = self._panel(self.create_tab, "Nova senha protegida")
        pane.pack(fill="both", expand=True)
        self.label_var = tk.StringVar()
        self.secret_var = tk.StringVar()
        self.master_var = tk.StringVar()
        self.master_again_var = tk.StringVar()
        self.export_also_var = tk.BooleanVar(value=False)
        self.create_status = tk.StringVar(value="Tudo é processado localmente. Nenhuma senha é enviada pela internet.")
        self._field(pane, "Identificador opcional (fica criptografado)", self.label_var)
        self.secret_entry = self._field(pane, "Senha que será guardada", self.secret_var, masked=True)
        actions = ttk.Frame(pane, style="Panel.TFrame")
        actions.pack(fill="x", pady=(8, 2))
        ttk.Button(actions, text="Gerar senha de 32 caracteres", command=self._generate).pack(side="left")
        self.secret_visible = tk.BooleanVar(value=False)
        ttk.Checkbutton(actions, text="Mostrar temporariamente", variable=self.secret_visible,
                        command=self._toggle_secret).pack(side="left", padx=13)
        self._field(pane, "Senha mestra (mínimo de 16 caracteres)", self.master_var, masked=True)
        self._field(pane, "Confirme a senha mestra", self.master_again_var, masked=True)
        self._label(pane, "Memorize ou guarde a senha mestra em um local seguro. Não existe recuperação automática.", True).pack(
            anchor="w", pady=(11, 4))
        ttk.Checkbutton(pane, text="Ao salvar no cofre, também exportar uma cópia criptografada",
                        variable=self.export_also_var).pack(anchor="w", pady=(8, 3))
        row = ttk.Frame(pane, style="Panel.TFrame")
        row.pack(fill="x", pady=(14, 7))
        self.vault_button = ttk.Button(row, text="Guardar no cofre Windows", style="Accent.TButton", command=self._save_vault)
        self.vault_button.pack(side="left", padx=(0, 11))
        if not self.vault:
            self.vault_button.configure(state="disabled")
        ttk.Button(row, text="Exportar arquivo cifrado", command=self._save_file).pack(side="left")
        self._label(pane, "O arquivo .txt exportado contém apenas dados criptografados, nunca a senha em texto aberto.", True).pack(
            anchor="w", pady=(7, 0))
        self.create_status_label = self._label(pane, "")
        self.create_status_label.configure(textvariable=self.create_status, wraplength=790)
        self.create_status_label.pack(anchor="w", pady=(4, 0))
        if self.vault_error:
            self._label(pane, "Cofre Windows indisponível: " + self.vault_error, True).pack(anchor="w", pady=7)

    def _build_recover(self):
        pane = self._panel(self.recover_tab, "Desbloquear um registro")
        pane.pack(fill="both", expand=True)
        self.recover_source_var = tk.StringVar(value="Nenhum registro selecionado")
        source_row = ttk.Frame(pane, style="Panel.TFrame")
        source_row.pack(fill="x", pady=(15, 6))
        ttk.Button(source_row, text="Selecionar arquivo .txt / .zip", command=self._choose_recover_file).pack(side="left")
        ttk.Button(source_row, text="Atualizar cofre", command=self._refresh_vault).pack(side="left", padx=9)
        self._label(pane, "Registro selecionado:", True).pack(anchor="w", pady=(8, 2))
        # The selected source is separately reflected in the always-visible status line.
        self.selected_source_label = self._label(pane, "Nenhum registro selecionado", True)
        self.selected_source_label.configure(textvariable=self.recover_source_var)
        self.selected_source_label.pack(anchor="w", pady=(2, 5))
        self._label(pane, "Itens do cofre vinculados à sua conta do Windows", True).pack(anchor="w", pady=(10, 5))
        list_frame = ttk.Frame(pane, style="Panel.TFrame")
        list_frame.pack(fill="x")
        self.vault_list = tk.Listbox(list_frame, height=5, selectmode="browse", bg=PANEL2, fg=FG,
                                     selectbackground=BORDER, selectforeground=FG, highlightthickness=0,
                                     relief="flat", borderwidth=0, font=("Consolas", 10), activestyle="none")
        self.vault_list.pack(fill="x", expand=False)
        self.vault_list.bind("<<ListboxSelect>>", self._select_vault)
        self.vault_ids: list[str] = []
        self._refresh_vault()
        self.recover_master_var = tk.StringVar()
        self._field(pane, "Senha mestra do registro", self.recover_master_var, masked=True)
        row = ttk.Frame(pane, style="Panel.TFrame")
        row.pack(fill="x", pady=(12, 8))
        ttk.Button(row, text="Desbloquear e recuperar", style="Accent.TButton", command=self._unlock).pack(side="left")
        ttk.Button(row, text="Bloquear agora", command=self._lock).pack(side="left", padx=10)
        row_vault = ttk.Frame(pane, style="Panel.TFrame")
        row_vault.pack(fill="x", pady=(0, 8))
        ttk.Button(row_vault, text="Exportar backup cifrado", command=self._export_vault_backup).pack(side="left")
        ttk.Button(row_vault, text="Excluir registro do cofre", command=self._delete_vault).pack(side="left", padx=10)
        self.recover_status = tk.StringVar(value="A senha só aparece após a verificação criptográfica.")
        ttk.Label(pane, textvariable=self.recover_status, style="PanelMuted.TLabel").pack(anchor="w", pady=(3, 6))
        self._label(pane, "Identificador recuperado", True).pack(anchor="w", pady=(9, 4))
        ttk.Label(pane, textvariable=self.recovered_label, style="Panel.TLabel").pack(anchor="w")
        self._label(pane, "Senha recuperada (oculta por padrão)", True).pack(anchor="w", pady=(11, 4))
        self.recover_output = ttk.Entry(pane, textvariable=self.recovered_password, show="●", state="readonly")
        self.recover_output.pack(fill="x")
        bottom = ttk.Frame(pane, style="Panel.TFrame")
        bottom.pack(fill="x", pady=(9, 0))
        ttk.Button(bottom, text="Mostrar por 15 segundos", command=self._show_recovered).pack(side="left")
        ttk.Button(bottom, text="Copiar (limpar em 20 s)", command=self._copy_recovered).pack(side="left", padx=9)

    def _build_disguise(self):
        pane = self._panel(self.disguise_tab, "Disfarçar sem comprometer a criptografia")
        pane.pack(fill="both", expand=True)
        self._label(pane, "Converta um arquivo já criptografado em um ZIP verdadeiro com nomes internos genéricos.", True).pack(
            anchor="w", pady=(17, 5))
        self._label(pane, "Um ZIP disfarça a apresentação, mas não acrescenta proteção criptográfica.", True).pack(
            anchor="w", pady=(0, 13))
        row = ttk.Frame(pane, style="Panel.TFrame")
        row.pack(fill="x", pady=(7, 12))
        ttk.Button(row, text="Escolher arquivo criptografado", command=self._choose_disguise_file).pack(side="left")
        self.disguise_source_var = tk.StringVar(value="Nenhum arquivo escolhido")
        ttk.Label(pane, textvariable=self.disguise_source_var, style="PanelMuted.TLabel").pack(anchor="w", pady=(5, 17))
        row2 = ttk.Frame(pane, style="Panel.TFrame")
        row2.pack(fill="x", pady=(4, 7))
        ttk.Button(row2, text="Criar ZIP discreto", style="Accent.TButton", command=self._create_zip).pack(side="left")
        ttk.Button(row2, text="Restaurar ZIP para arquivo cifrado", command=self._restore_zip).pack(side="left", padx=11)
        self.disguise_status = tk.StringVar(value="O ZIP pode ser aberto pelo próprio aplicativo na aba Recuperar.")
        ttk.Label(pane, textvariable=self.disguise_status, style="PanelMuted.TLabel",
                  wraplength=745).pack(anchor="w", pady=(25, 7))
        sep = ttk.Separator(pane, orient="horizontal")
        sep.pack(fill="x", pady=(22, 20))
        self._label(pane, "O que acontece com seus dados").pack(anchor="w", pady=(0, 10))
        self._label(pane, "1. Sua senha original permanece criptografada com AES-256-GCM.", True).pack(anchor="w", pady=4)
        self._label(pane, "2. O ZIP contém somente o arquivo já criptografado.", True).pack(anchor="w", pady=4)
        self._label(pane, "3. A restauração nunca extrai uma senha em texto simples.", True).pack(anchor="w", pady=4)

    def _touch(self, _event=None):
        if self._idle_timer is not None:
            self.after_cancel(self._idle_timer)
        self._idle_timer = self.after(60_000, self._lock)

    def _on_tab_changed(self, _event=None):
        if self.tabs.index(self.tabs.select()) != 1:
            self._lock()

    def _lock(self):
        self._clear_clipboard()
        if self._reveal_timer is not None:
            self.after_cancel(self._reveal_timer)
            self._reveal_timer = None
        self.recovered_password.set("")
        self.recovered_label.set("")
        self.recover_output.configure(show="●")
        self.recover_master_var.set("")
        self.master_var.set("")
        self.master_again_var.set("")
        self.secret_var.set("")
        self.secret_visible.set(False)
        self.secret_entry.configure(show="●")
        self.recover_status.set("Bloqueado. Campos sensíveis limpos.")
        self._touch()

    def _generate(self):
        self.secret_var.set(generate_password())
        self.secret_visible.set(True)
        self._toggle_secret()
        self.after(15_000, self._hide_secret)

    def _hide_secret(self):
        self.secret_visible.set(False)
        self._toggle_secret()

    def _toggle_secret(self):
        self.secret_entry.configure(show="" if self.secret_visible.get() else "●")

    def _encryption_input(self):
        master = self.master_var.get()
        if master != self.master_again_var.get():
            raise VaultError("A confirmação da senha mestra não corresponde.")
        return encrypt_secret(self.secret_var.get(), master, self.label_var.get().strip())

    def _saved(self, text):
        self.create_status.set(text)
        self.secret_var.set("")
        self.label_var.set("")
        self.master_var.set("")
        self.master_again_var.set("")
        self._hide_secret()

    def _ask_export_path(self, extension=".txt"):
        return filedialog.asksaveasfilename(
            parent=self, title="Salvar dados criptografados",
            initialfile=f"registro_{secrets.token_hex(4)}{extension}",
            defaultextension=extension,
            filetypes=[("Arquivos de dados criptografados", "*.txt"), ("Todos os arquivos", "*.*")]
        )

    def _save_file(self):
        try:
            encrypted = self._encryption_input()
            path = self._ask_export_path()
            if not path:
                return
            atomic_write(path, encrypted)
            self._saved("Arquivo criptografado salvo em: " + str(path))
        except (VaultError, OSError, ValueError) as exc:
            messagebox.showerror("Não foi possível exportar", str(exc), parent=self)

    def _save_vault(self):
        try:
            if not self.vault:
                raise VaultError("Cofre Windows indisponível.")
            encrypted = self._encryption_input()
            copy_path = None
            if self.export_also_var.get():
                copy_path = self._ask_export_path()
                if not copy_path:
                    return
            identifier = self.vault.store(encrypted)
            if copy_path:
                try:
                    atomic_write(copy_path, encrypted)
                except OSError as exc:
                    self._saved(f"Registro salvo no cofre ({identifier}), mas a exportação falhou: {exc}")
                    messagebox.showwarning("Cofre salvo", "Cofre salvo; cópia externa não pôde ser gravada.", parent=self)
                    self._refresh_vault()
                    return
            self._saved("Registro protegido no cofre Windows (ID " + identifier[:10] + "…).")
            self._refresh_vault()
        except (VaultError, OSError, ValueError) as exc:
            messagebox.showerror("Não foi possível guardar", str(exc), parent=self)

    def _refresh_vault(self):
        self.vault_list.delete(0, "end")
        self.vault_ids.clear()
        if not self.vault:
            self.vault_list.insert("end", "Cofre disponível somente no Windows com dependências instaladas")
            return
        try:
            for identifier, timestamp in self.vault.list_entries():
                self.vault_ids.append(identifier)
                self.vault_list.insert("end", f"{timestamp}     {identifier[:16]}…")
        except OSError as exc:
            self.recover_status.set("Não foi possível listar os registros: " + str(exc)) if hasattr(self, "recover_status") else None
        if not self.vault_ids:
            self.vault_list.insert("end", "Nenhum registro no cofre")

    def _select_vault(self, _event=None):
        selection = self.vault_list.curselection()
        if selection and selection[0] < len(self.vault_ids):
            self.source_id = self.vault_ids[selection[0]]
            self.source_file = None
            self.recover_source_var.set("Cofre Windows  /  " + self.source_id[:16] + "…")
            self._clear_recovered_only()

    def _choose_recover_file(self):
        path = filedialog.askopenfilename(parent=self, title="Abrir arquivo criptografado",
                                           filetypes=[("Cofre criptografado ou ZIP", "*.txt *.zip *.bin *.dat"),
                                                      ("Todos os arquivos", "*.*")])
        if path:
            self.source_file = Path(path)
            self.source_id = None
            self.vault_list.selection_clear(0, "end")
            self.recover_source_var.set("Arquivo  /  " + self.source_file.name)
            self._clear_recovered_only()

    def _clear_recovered_only(self):
        self.recovered_password.set("")
        self.recovered_label.set("")
        self.recover_output.configure(show="●")

    def _unlock(self):
        if time.monotonic() < self.next_unlock_time:
            self.recover_status.set("Muitas tentativas. Tente novamente após alguns segundos.")
            return
        try:
            if self.source_id:
                if self.vault is None:
                    raise VaultError("Cofre do Windows indisponível.")
                blob = self.vault.load(self.source_id)
            elif self.source_file:
                blob = read_encrypted_file(self.source_file)
            else:
                raise VaultError("Selecione um registro do cofre ou um arquivo.")
            password, label = decrypt_secret(blob, self.recover_master_var.get())
            self.recovered_password.set(password)
            self.recovered_label.set(label or "Sem identificador")
            self.recover_master_var.set("")
            self.recover_status.set("Autenticidade verificada. Bloqueio automático em 60 s de inatividade.")
            self.failed_attempts = 0
            self.next_unlock_time = 0.0
        except (VaultError, OSError, ValueError, PermissionError) as exc:
            self._clear_recovered_only()
            self.failed_attempts += 1
            if self.failed_attempts >= 3:
                self.next_unlock_time = time.monotonic() + min(60, 10 * (self.failed_attempts - 2))
            self.recover_status.set("Não foi possível desbloquear. Confira a origem e a senha mestra.")
            messagebox.showerror("Acesso negado", str(exc), parent=self)

    def _show_recovered(self):
        if not self.recovered_password.get():
            return
        self.recover_output.configure(show="")
        if self._reveal_timer is not None:
            self.after_cancel(self._reveal_timer)
        self._reveal_timer = self.after(15_000, lambda: self.recover_output.configure(show="●"))

    def _copy_recovered(self):
        secret = self.recovered_password.get()
        if not secret:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(secret)
            self.update_idletasks()
            self.clipboard_digest = hashlib.sha256(secret.encode("utf-8")).digest()
            self.recover_status.set("Copiado. Tentativa de limpar a área de transferência em 20 segundos.")
            if self._clipboard_timer:
                self.after_cancel(self._clipboard_timer)
            self._clipboard_timer = self.after(20_000, self._clear_clipboard)
        except tk.TclError:
            messagebox.showwarning("Área de transferência", "Não foi possível copiar a senha.", parent=self)

    def _clear_clipboard(self):
        try:
            if self.clipboard_digest and hmac.compare_digest(
                hashlib.sha256(self.clipboard_get().encode("utf-8")).digest(), self.clipboard_digest
            ):
                self.clipboard_clear()
        except tk.TclError:
            pass
        self.clipboard_digest = None

    def _authorize_vault_action(self, encrypted: bytes, action: str) -> bool:
        """Recheck the master password for sensitive UI actions.

        This limits casual access to these buttons; it cannot stop malicious
        programs running with the same Windows account privileges.
        """
        master = simpledialog.askstring(
            "Confirmar autorização",
            f"Digite a senha mestra deste registro para {action}:",
            show="●", parent=self,
        )
        if master is None:
            return False
        try:
            # AES-GCM authentication is the actual password check.
            decrypt_secret(encrypted, master)
        except VaultError as exc:
            self.recover_status.set("Autorização negada: senha mestra não confirmada.")
            raise VaultError("Não foi possível confirmar a senha mestra.") from exc
        return True

    def _export_vault_backup(self):
        """Export only authenticated ciphertext after reauthentication."""
        try:
            if not self.vault or not self.source_id:
                raise VaultError("Selecione primeiro um registro do cofre Windows.")
            encrypted = self.vault.load(self.source_id)
            if not self._authorize_vault_action(encrypted, "exportar o backup"):
                return
            out = self._ask_export_path()
            if out:
                atomic_write(out, encrypted)
                self.recover_status.set("Backup criptografado exportado. Teste-o antes de excluir qualquer cópia.")
        except (VaultError, OSError, ValueError) as exc:
            messagebox.showerror("Falha no backup", str(exc), parent=self)

    def _delete_vault(self):
        try:
            if not self.vault or not self.source_id:
                raise VaultError("Selecione primeiro um registro do cofre Windows.")
            if not messagebox.askyesno(
                "Confirmar exclusão",
                "Excluir este registro do cofre?\n\nFaça e teste o backup externo antes. "
                "A exclusão comum NÃO garante remoção forense no SSD.",
                icon="warning", parent=self,
            ):
                return
            encrypted = self.vault.load(self.source_id)
            if not self._authorize_vault_action(encrypted, "excluir o registro"):
                return
            self.vault.delete(self.source_id)
            self._lock()
            self.source_id = None
            self.source_file = None
            self.recover_source_var.set("Nenhuma origem selecionada")
            self._refresh_vault()
            self.recover_status.set("Registro excluído do cofre local.")
        except (VaultError, OSError, ValueError) as exc:
            messagebox.showerror("Falha ao excluir", str(exc), parent=self)

    def _choose_disguise_file(self):
        path = filedialog.askopenfilename(parent=self, title="Arquivo previamente criptografado",
                                           filetypes=[("Arquivos criptografados", "*.txt *.bin *.dat *.zip"),
                                                      ("Todos os arquivos", "*.*")])
        if path:
            self.disguise_file = Path(path)
            self.disguise_source_var.set("Origem: " + self.disguise_file.name)

    def _create_zip(self):
        try:
            if not self.disguise_file:
                raise VaultError("Selecione primeiro um arquivo criptografado.")
            encrypted = read_encrypted_file(self.disguise_file)
            out = filedialog.asksaveasfilename(parent=self, title="Salvar ZIP discreto",
                                                initialfile="arquivos_" + secrets.token_hex(4) + ".zip",
                                                defaultextension=".zip",
                                                filetypes=[("Arquivo ZIP", "*.zip")])
            if not out:
                return
            if Path(out).resolve() == self.disguise_file.resolve():
                raise VaultError("Escolha um nome de saída diferente do original.")
            disguise_as_zip(encrypted, out)
            self.disguise_status.set("ZIP real criado, com conteúdo cifrado: " + out)
        except (VaultError, OSError, ValueError) as exc:
            messagebox.showerror("Falha ao disfarçar", str(exc), parent=self)

    def _restore_zip(self):
        try:
            inp = filedialog.askopenfilename(parent=self, title="Selecionar ZIP gerado pelo aplicativo",
                                              filetypes=[("Arquivo ZIP", "*.zip")])
            if not inp:
                return
            if Path(inp).suffix.lower() != ".zip":
                raise VaultError("Selecione um arquivo .zip criado pelo aplicativo.")
            encrypted = read_encrypted_file(inp)
            out = self._ask_export_path()
            if not out:
                return
            if Path(inp).resolve() == Path(out).resolve():
                raise VaultError("Escolha um destino diferente do ZIP original.")
            atomic_write(out, encrypted)
            self.disguise_status.set("Conteúdo cifrado restaurado sem revelar senha: " + out)
        except (VaultError, OSError, ValueError) as exc:
            messagebox.showerror("Falha na restauração", str(exc), parent=self)

    def _close(self):
        self._clear_clipboard()
        self._lock()
        self.destroy()


if __name__ == "__main__":
    if sys.version_info < (3, 11):
        raise SystemExit("Instale Python 3.11 ou superior.")
    try:
        LocalVaultApp().mainloop()
    except tk.TclError as exc:
        raise SystemExit(f"Não foi possível abrir a interface: {exc}")
