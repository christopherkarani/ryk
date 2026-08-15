import type { LucideIcon } from "lucide-react";
import { Activity, FileCode, LayoutDashboard, Plug, ShieldCheck, TerminalSquare } from "lucide-react";

export type NavTabId = "overview" | "secretless" | "activity" | "terminal" | "policy" | "integrations";

export interface NavTab {
  id: NavTabId;
  label: string;
  shortLabel: string;
  href: string;
  icon: LucideIcon;
}

export const NAV_TABS: NavTab[] = [
  { id: "overview", label: "Overview", shortLabel: "Home", href: "/", icon: LayoutDashboard },
  { id: "secretless", label: "Secretless", shortLabel: "Secrets", href: "/secretless/", icon: ShieldCheck },
  { id: "activity", label: "Activity", shortLabel: "Activity", href: "/activity/", icon: Activity },
  { id: "terminal", label: "Terminal", shortLabel: "Term.", href: "/terminal/", icon: TerminalSquare },
  { id: "policy", label: "Policy", shortLabel: "Policy", href: "/policy/", icon: FileCode },
  { id: "integrations", label: "Integrations", shortLabel: "Integr.", href: "/integrations/", icon: Plug },
];

export function visibleNavigation(mode: "machine" | "workspace"): NavTab[] {
  if (mode === "workspace") return NAV_TABS;
  return NAV_TABS.filter((tab) => tab.id !== "policy" && tab.id !== "secretless");
}

export function isNavTabActive(pathname: string, href: string): boolean {
  if (href === "/") {
    return pathname === "/" || pathname === "";
  }

  const base = href.endsWith("/") ? href.slice(0, -1) : href;
  return (
    pathname === href ||
    pathname === base ||
    pathname === `${base}/` ||
    pathname.startsWith(`${base}/`)
  );
}
