import { cn } from "./cn";

export interface StrengthMeterProps {
  /** 0 (very weak) to 4 (very strong). */
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  className?: string;
}

const colors = ["bg-danger", "bg-danger", "bg-warning", "bg-success", "bg-success"];
const text = ["text-danger", "text-danger", "text-warning-text", "text-success-text", "text-success-text"];

export function StrengthMeter({ score, label, className }: StrengthMeterProps) {
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div className="flex flex-1 gap-1" aria-hidden="true">
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={cn("h-1 flex-1 rounded-full", i < Math.max(score, 1) ? colors[score] : "bg-border")}
          />
        ))}
      </div>
      <span className={cn("text-xs font-medium whitespace-nowrap", text[score])}>{label}</span>
    </div>
  );
}
