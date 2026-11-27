import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex h-8 items-center justify-center gap-2 border px-3 text-[10px] uppercase tracking-[0.08em] transition-colors disabled:pointer-events-none disabled:opacity-40",
  {
    variants: {
      variant: {
        default: "border-[#65d98a] bg-[#65d98a] text-[#09100b] hover:bg-[#8ae6a4]",
        outline: "border-[#354839] bg-transparent text-[#c5d5c7] hover:border-[#65d98a] hover:text-[#65d98a]",
        danger: "border-[#653c35] bg-transparent text-[#d67668] hover:bg-[#291916]",
        quiet: "border-transparent bg-transparent text-[#718276] hover:text-[#c5d5c7]",
      },
      size: {
        default: "h-8 px-3",
        small: "h-7 px-2",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
  };

export function Button({
  asChild = false,
  className,
  size,
  variant,
  ...props
}: ButtonProps) {
  const Component = asChild ? Slot : "button";
  return (
    <Component
      className={cn(buttonVariants({ className, size, variant }))}
      {...props}
    />
  );
}
