import { useEffect, useState } from "react";

const KEY = "osintcc.advanced";
const EVENT = "osintcc:mode";

function read(): boolean {
  try { return localStorage.getItem(KEY) === "1"; } catch { return false; }
}

/** Simple mode is the default. Advanced mode shows the whole workbench; it only changes what is visible, never stored records. Persisted per device. */
export function useAdvanced(): [boolean, (v: boolean) => void] {
  const [adv, setAdv] = useState(read);
  useEffect(() => {
    const on = () => setAdv(read());
    window.addEventListener(EVENT, on);
    window.addEventListener("storage", on);
    return () => { window.removeEventListener(EVENT, on); window.removeEventListener("storage", on); };
  }, []);
  const set = (v: boolean) => {
    try { localStorage.setItem(KEY, v ? "1" : "0"); } catch { /* the choice still applies for this page load */ }
    setAdv(v);
    window.dispatchEvent(new Event(EVENT));
  };
  return [adv, set];
}
