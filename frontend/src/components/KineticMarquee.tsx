export function KineticMarquee({
  items,
  speed = "fast",
  label
}: {
  items: string[];
  speed?: "fast" | "slow";
  label: string;
}) {
  const content = items.flatMap((item, index) => [
    <span className="marquee-item" key={`${index}-${item}`}>
      {item}
    </span>,
    <span className="marquee-marker" aria-hidden="true" key={`${index}-marker`}>
      ✦
    </span>
  ]);
  return (
    <div className={`kinetic-marquee marquee-${speed}`} aria-label={label}>
      <div className="marquee-track">
        <div className="marquee-content">{content}</div>
        <div className="marquee-content" aria-hidden="true">
          {content}
        </div>
      </div>
    </div>
  );
}
