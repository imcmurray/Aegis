/**
 * Scroll-scrubbed marketing scenes. Motion is WAAPI so production CSP
 * (style-src 'self', no unsafe-inline) still allows it.
 */

type Frames = Keyframe[];
type Scene = Record<string, Frames>;

const compact = window.matchMedia("(max-width: 720px)").matches;
const dockX = compact ? "31vw" : "24vw";
const syncTo = compact ? "0 -7.6rem" : "-19vw 0";
const shareTo = compact ? "0 7.4rem" : "19vw 0";

const scenes: Record<string, Scene> = {
  mark: {
    halo: [
      { opacity: 0.15, scale: "0.65", offset: 0 },
      { opacity: 1, scale: "1", offset: 1 },
    ],
    ring: [
      { strokeDashoffset: 289, opacity: 0.15, offset: 0 },
      { strokeDashoffset: 0, opacity: 1, offset: 1 },
    ],
    icon: [
      { scale: "0.72", opacity: 0.45, offset: 0 },
      { scale: "1", opacity: 1, offset: 1 },
    ],
    caption: [
      { opacity: 0, transform: "translate(-50%, 18px)", offset: 0 },
      { opacity: 0, transform: "translate(-50%, 18px)", offset: 0.4 },
      { opacity: 1, transform: "translate(-50%, 0)", offset: 1 },
    ],
    cue: [
      { opacity: 0.85, offset: 0 },
      { opacity: 0, offset: 0.28 },
      { opacity: 0, offset: 1 },
    ],
  },
  quantum: {
    halo: [
      { opacity: 0.2, scale: "0.75", offset: 0 },
      { opacity: 1, scale: "1.2", offset: 1 },
    ],
    icon: [
      { scale: "0.88", offset: 0 },
      { scale: "1", offset: 1 },
    ],
    classic: [
      { translate: "-34vw 0", opacity: 0.15, offset: 0 },
      { translate: "-16vw 0", opacity: 1, offset: 0.42 },
      { translate: "0 0", opacity: 0, offset: 0.78 },
      { translate: "0 0", opacity: 0, offset: 1 },
    ],
    lattice: [
      { translate: "34vw 0", opacity: 0.15, offset: 0 },
      { translate: "16vw 0", opacity: 1, offset: 0.42 },
      { translate: "0 0", opacity: 0, offset: 0.78 },
      { translate: "0 0", opacity: 0, offset: 1 },
    ],
    x25519: dock("-32vw 1.2rem", `-${dockX} -2.6rem`),
    ed25519: dock("-30vw 3.4rem", `-${dockX} 2.6rem`),
    kem: dock("32vw -1.2rem", `${dockX} -2.6rem`),
    dsa: dock("30vw 3.2rem", `${dockX} 2.6rem`),
    caption: lateCaption(),
  },
  hybrid: {
    icon: [
      { scale: "0.92", offset: 0 },
      { scale: "1", offset: 1 },
    ],
    sync: slide("-40vw 0", syncTo),
    share: slide("40vw 0", shareTo),
    caption: lateCaption(),
    note: lateCaption(),
  },
  offline: {
    net: [
      { opacity: 0.95, offset: 0 },
      { opacity: 0.85, offset: 0.25 },
      { opacity: 0, offset: 0.72 },
      { opacity: 0, offset: 1 },
    ],
    icon: [
      { translate: "0 -240px", opacity: 0.35, offset: 0 },
      { translate: "0 -240px", opacity: 0.7, offset: 0.16 },
      { translate: "0 0", opacity: 1, offset: 0.62 },
      { translate: "0 0", opacity: 1, offset: 1 },
    ],
    chip: [
      { opacity: 0, translate: "0 12px", offset: 0 },
      { opacity: 0, translate: "0 12px", offset: 0.55 },
      { opacity: 1, translate: "0 0", offset: 0.82 },
      { opacity: 1, translate: "0 0", offset: 1 },
    ],
    caption: lateCaption(),
  },
  link: {
    bridge: [
      { opacity: 0.15, offset: 0 },
      { opacity: 0.85, offset: 0.35 },
      { opacity: 0.85, offset: 1 },
    ],
    bead: [
      { left: "0%", opacity: 0, offset: 0 },
      { left: "0%", opacity: 1, offset: 0.12 },
      { left: "100%", opacity: 1, offset: 0.68 },
      { left: "100%", opacity: 0, offset: 0.86 },
      { left: "100%", opacity: 0, offset: 1 },
    ],
    rows: [
      { opacity: 0, translate: "0 10px", offset: 0 },
      { opacity: 0, translate: "0 10px", offset: 0.62 },
      { opacity: 1, translate: "0 0", offset: 0.88 },
      { opacity: 1, translate: "0 0", offset: 1 },
    ],
    chip: [
      { opacity: 0, translate: "0 12px", offset: 0 },
      { opacity: 0, translate: "0 12px", offset: 0.5 },
      { opacity: 1, translate: "0 0", offset: 0.78 },
      { opacity: 1, translate: "0 0", offset: 1 },
    ],
    caption: lateCaption(),
  },
  ways: {
    browser: rise(0.12),
    backup: rise(0.32),
    peer: rise(0.52),
    caption: lateCaption(),
  },
};

function dock(from: string, to: string): Frames {
  return [
    { translate: from, opacity: 0, offset: 0 },
    { translate: from, opacity: 0, offset: 0.34 },
    { translate: to, opacity: 1, offset: 0.78 },
    { translate: to, opacity: 1, offset: 1 },
  ];
}

function slide(from: string, to: string): Frames {
  return [
    { translate: from, opacity: 0, offset: 0 },
    { translate: from, opacity: 0, offset: 0.12 },
    { translate: to, opacity: 1, offset: 0.62 },
    { translate: to, opacity: 1, offset: 1 },
  ];
}

function rise(delay: number): Frames {
  const shown = Math.min(0.92, delay + 0.28);
  return [
    { opacity: 0, translate: "0 36px", offset: 0 },
    { opacity: 0, translate: "0 36px", offset: delay },
    { opacity: 1, translate: "0 0", offset: shown },
    { opacity: 1, translate: "0 0", offset: 1 },
  ];
}

function lateCaption(): Frames {
  return [
    { opacity: 0, transform: "translate(-50%, 16px)", offset: 0 },
    { opacity: 0, transform: "translate(-50%, 16px)", offset: 0.58 },
    { opacity: 1, transform: "translate(-50%, 0)", offset: 0.86 },
    { opacity: 1, transform: "translate(-50%, 0)", offset: 1 },
  ];
}

const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function progress(section: HTMLElement): number {
  const travel = section.offsetHeight - window.innerHeight;
  if (travel <= 0) return 1;
  const scrolled = -section.getBoundingClientRect().top;
  return Math.min(1, Math.max(0, scrolled / travel));
}

function bind(section: HTMLElement): Animation[] {
  const spec = scenes[section.dataset.scene ?? ""];
  if (!spec) return [];
  const anims: Animation[] = [];
  for (const [name, frames] of Object.entries(spec)) {
    const node = section.querySelector(`[data-piece="${name}"]`);
    if (!node) continue;
    const anim = node.animate(frames, {
      duration: 1000,
      fill: "both",
      easing: "linear",
    });
    anim.pause();
    anims.push(anim);
  }
  return anims;
}

function main() {
  const sections = [...document.querySelectorAll<HTMLElement>(".scene")];
  if (reduce) return;

  const bound = sections.map((section) => ({ section, anims: bind(section) }));

  const apply = () => {
    for (const { section, anims } of bound) {
      const time = progress(section) * 1000;
      for (const anim of anims) anim.currentTime = time;
    }
  };

  let scheduled = false;
  const requestTick = () => {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      apply();
    });
  };

  document.addEventListener("scroll", requestTick, { passive: true });
  window.addEventListener("resize", requestTick);
  apply();
}

main();
