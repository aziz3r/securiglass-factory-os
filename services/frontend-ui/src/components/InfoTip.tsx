import { useEffect, useId, useRef, useState, type ReactNode } from 'react';

/**
 * Bouton « i » : explique en langage simple. S'ouvre au clic, au clavier (Entrée/Espace)
 * et se ferme avec Échap ou un clic ailleurs. Aucun style inline (CSP stricte).
 */
export function InfoTip({ label, children }: { label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const root = useRef<HTMLSpanElement | null>(null);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    function onPointer(event: MouseEvent): void {
      if (root.current !== null && !root.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    function onKey(event: KeyboardEvent): void {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <span className="infotip" ref={root}>
      <button
        type="button"
        className="infotip-button"
        aria-label={`Information : ${label}`}
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((v) => !v)}
      >
        i
      </button>
      {open ? (
        <span role="note" id={id} className="infotip-bubble">
          {children}
        </span>
      ) : null}
    </span>
  );
}
