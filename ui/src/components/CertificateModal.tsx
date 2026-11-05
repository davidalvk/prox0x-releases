import { useState } from "react";
import { createPortal } from "react-dom";
import { Download, ShieldCheck, Terminal, X } from "lucide-react";
import { HelpTooltip } from "./HelpTooltip";

type GuideTab = "firefox" | "chrome" | "system";

interface CertificateModalProps {
  showTooltip?: boolean;
}

export function CertificateModal({ showTooltip = true }: CertificateModalProps) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<GuideTab>("firefox");

  return (
    <>
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="flex items-center gap-2 rounded-lg border border-cyan-400/50 bg-cyan-950/35 px-3 py-2 text-xs font-semibold text-cyan-300 transition hover:border-accent hover:text-accent"
        >
          <ShieldCheck size={15} className="text-accent" />
          Certificado CA
        </button>
        {showTooltip && (
          <HelpTooltip
            label="Certificado CA"
            text="Descarga e instala el certificado raíz de prox0x para interceptar tráfico HTTPS sin errores."
          />
        )}
      </div>

      {open &&
        createPortal(
          <div
            className="fixed inset-0 z-[70] flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
            onClick={() => setOpen(false)}
            role="presentation"
          >
            <section
              role="dialog"
              aria-label="Certificado CA"
              onClick={(event) => event.stopPropagation()}
              className="terminal-modal flex max-h-[88vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-accent bg-surface-900 shadow-2xl"
            >
              <header className="flex items-center justify-between border-b border-surface-700 px-5 py-4">
                <div className="flex items-center gap-2.5">
                  <div className="grid h-8 w-8 place-items-center rounded border border-accent/60 bg-accent/10 text-accent">
                    <ShieldCheck size={17} />
                  </div>
                  <div>
                    <h2 className="text-sm font-semibold text-accent">
                      Certificado CA (HTTPS)
                    </h2>
                    <p className="text-[11px] text-zinc-500">
                      Autoridad de certificación raíz local ECDSA P-256
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  aria-label="Cerrar Certificado CA"
                  className="rounded-lg border border-surface-700 p-2 text-zinc-400 hover:text-zinc-100"
                >
                  <X size={16} />
                </button>
              </header>

              <div className="space-y-5 overflow-auto p-5">
                <p className="rounded-xl border border-surface-700 bg-surface-950/70 p-3.5 text-xs leading-relaxed text-zinc-300">
                  Para interceptar tráfico HTTPS, prox0x necesita generar
                  certificados al vuelo. Instala esta CA en tu navegador para
                  evitar errores de conexión.
                </p>

                <a
                  href="/api/certificate"
                  download="prox0x-ca.pem"
                  className="flex w-full items-center justify-center gap-2.5 rounded-xl border border-accent bg-accent px-5 py-3 text-xs font-bold uppercase tracking-wider text-surface-950 shadow-glow transition hover:bg-accent-soft"
                >
                  <Download size={16} />
                  Descargar Certificado CA
                </a>

                <div className="space-y-3">
                  <div
                    role="tablist"
                    aria-label="Guía de instalación por plataforma"
                    className="flex flex-wrap gap-1.5 border-b border-surface-800 pb-2"
                  >
                    <button
                      type="button"
                      role="tab"
                      aria-selected={tab === "firefox"}
                      onClick={() => setTab("firefox")}
                      className={[
                        "rounded-lg border px-3 py-1.5 text-xs font-semibold transition",
                        tab === "firefox"
                          ? "border-accent bg-accent/15 text-accent"
                          : "border-surface-700 bg-surface-950 text-zinc-400",
                      ].join(" ")}
                    >
                      Firefox
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={tab === "chrome"}
                      onClick={() => setTab("chrome")}
                      className={[
                        "rounded-lg border px-3 py-1.5 text-xs font-semibold transition",
                        tab === "chrome"
                          ? "border-accent bg-accent/15 text-accent"
                          : "border-surface-700 bg-surface-950 text-zinc-400",
                      ].join(" ")}
                    >
                      Chrome / Edge
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={tab === "system"}
                      onClick={() => setTab("system")}
                      className={[
                        "rounded-lg border px-3 py-1.5 text-xs font-semibold transition",
                        tab === "system"
                          ? "border-accent bg-accent/15 text-accent"
                          : "border-surface-700 bg-surface-950 text-zinc-400",
                      ].join(" ")}
                    >
                      Sistema (Windows/macOS/Linux)
                    </button>
                  </div>

                  {tab === "firefox" && (
                    <div className="space-y-2 rounded-xl border border-surface-800 bg-surface-950 p-4 text-xs text-zinc-300">
                      <p className="font-semibold text-cyan-400">
                        Pasos en Mozilla Firefox:
                      </p>
                      <ol className="list-inside list-decimal space-y-1.5 text-zinc-300">
                        <li>
                          Abre{" "}
                          <span className="font-semibold text-accent">
                            Ajustes &gt; Privacidad y Seguridad &gt; Certificados
                            &gt; Ver Certificados &gt; Autoridades &gt; Importar
                          </span>
                          .
                        </li>
                        <li>
                          Selecciona el archivo descargado{" "}
                          <code className="text-cyan-400">prox0x-ca.pem</code>.
                        </li>
                        <li>
                          Marca la casilla{" "}
                          <span className="font-semibold text-amber-400">
                            &quot;Confiar en esta CA para identificar sitios
                            web&quot;
                          </span>{" "}
                          y acepta.
                        </li>
                      </ol>
                    </div>
                  )}

                  {tab === "chrome" && (
                    <div className="space-y-2 rounded-xl border border-surface-800 bg-surface-950 p-4 text-xs text-zinc-300">
                      <p className="font-semibold text-cyan-400">
                        Pasos en Google Chrome / Chromium / Microsoft Edge:
                      </p>
                      <ol className="list-inside list-decimal space-y-1.5 text-zinc-300">
                        <li>
                          Abre{" "}
                          <span className="font-semibold text-accent">
                            Configuración &gt; Privacidad y seguridad &gt;
                            Seguridad &gt; Gestionar certificados &gt;
                            Autoridades de certificación &gt; Importar
                          </span>
                          .
                        </li>
                        <li>
                          Selecciona{" "}
                          <code className="text-cyan-400">prox0x-ca.pem</code> y
                          activa la confianza para identificar sitios web.
                        </li>
                        <li>
                          Reinicia el navegador para aplicar la nueva autoridad.
                        </li>
                      </ol>
                    </div>
                  )}

                  {tab === "system" && (
                    <div className="space-y-2.5 rounded-xl border border-surface-800 bg-surface-950 p-4 font-mono text-[11px] text-zinc-300">
                      <p className="flex items-center gap-1.5 font-semibold text-cyan-400">
                        <Terminal size={13} />
                        Instalación en el almacén del sistema:
                      </p>
                      <div>
                        <p className="text-[10px] uppercase text-zinc-500">
                          Linux (Fedora / RHEL / Arch):
                        </p>
                        <code className="block text-accent">
                          sudo cp prox0x-ca.pem
                          /etc/pki/ca-trust/source/anchors/ &amp;&amp; sudo
                          update-ca-trust
                        </code>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase text-zinc-500">
                          Linux (Debian / Ubuntu / Kali):
                        </p>
                        <code className="block text-accent">
                          sudo cp prox0x-ca.pem
                          /usr/local/share/ca-certificates/prox0x-ca.crt
                          &amp;&amp; sudo update-ca-certificates
                        </code>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase text-zinc-500">
                          macOS:
                        </p>
                        <code className="block text-accent">
                          sudo security add-trusted-cert -d -r trustRoot -k
                          /Library/Keychains/System.keychain prox0x-ca.pem
                        </code>
                      </div>
                      <div>
                        <p className="text-[10px] uppercase text-zinc-500">
                          Windows (PowerShell Administrador):
                        </p>
                        <code className="block text-accent">
                          certutil -addstore -f &quot;ROOT&quot; prox0x-ca.pem
                        </code>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <footer className="flex items-center justify-between border-t border-surface-800 px-5 py-3">
                <span className="font-mono text-[10px] text-zinc-500">
                  Archivo: prox0x-ca.pem (X.509 PEM)
                </span>
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  className="rounded-lg border border-surface-700 px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-100"
                >
                  Cerrar
                </button>
              </footer>
            </section>
          </div>,
          document.body,
        )}
    </>
  );
}
