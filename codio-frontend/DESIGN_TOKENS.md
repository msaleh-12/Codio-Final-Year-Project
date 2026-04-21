# Codio Frontend Design Tokens

This guide captures the core visual system so new UI stays consistent.

## 1) Color System

Source of truth: app/globals.css custom properties.

Primary intent:
- Primary: action and emphasis
- Accent: secondary emphasis and highlights
- Muted: supporting surfaces and quiet information
- Border and Input: structural rhythm

Usage:
- Main CTAs use primary with strong contrast.
- Accent is used sparingly for progress or supportive highlights.
- Use card plus border values for layered surfaces.

## 2) Typography

Fonts:
- Sans: Sora
- Mono: Space Mono

Hierarchy:
- Hero headings: semibold with tight tracking.
- Section headings: medium or semibold.
- Body and helper text: muted foreground with balanced line length.
- Code or metrics: mono where scannability matters.

## 3) Surfaces and Depth

Surface class:
- surface-glass

Interactive depth class:
- interactive-lift

Guidelines:
- Use glass surfaces for major containers and overlays.
- Use lift only for cards or actionable groups, not every element.
- Keep spacing generous to preserve the premium look.

## 4) Motion and Transitions

Entry and reveal:
- stagger-in
- view-stage
- is-exiting

Ambient motion:
- float-soft
- shimmer-line

Guidelines:
- Use one primary animation per region.
- Prefer meaningful transitions between states over constant micro-motion.
- Respect reduced-motion settings already defined in globals.

## 5) Layout Principles

- Use rounded large containers for major sections.
- Combine atmosphere plus content, not flat single-color blocks.
- Keep desktop and mobile parity by stacking major panels on small screens.
- Maintain clear visual anchors: hero, input area, contextual status.

## 6) Component Styling Checklist

Before shipping a new component, verify:
- Uses shared color tokens instead of hard-coded colors.
- Uses Sora and Space Mono hierarchy correctly.
- Uses surface-glass or existing card styling for major shells.
- Includes hover and focus states for interactive controls.
- Works in both desktop and mobile widths.
- Avoids animation overload and remains readable.

## 7) Suggested Extension Pattern

When adding a new feature panel:
1. Start with surface-glass and border token usage.
2. Add one icon plus concise heading and helper copy.
3. Add one interaction animation only if it supports comprehension.
4. Validate contrast and focus states.
5. Keep spacing and rhythm aligned with dashboard and auth sections.
