import { FINDING_CATEGORIES, type FindingCategory } from "../lib/types";
import { labelize } from "../lib/format";

export function CategoryPicker({
  value,
  onChange,
  idPrefix = "category",
}: {
  value: FindingCategory[];
  onChange: (value: FindingCategory[]) => void;
  idPrefix?: string;
}) {
  function toggle(category: FindingCategory) {
    onChange(
      value.includes(category)
        ? value.filter((item) => item !== category)
        : [...value, category],
    );
  }

  return (
    <fieldset className="chip-fieldset">
      <legend>Assessment categories</legend>
      <div className="chip-grid">
        {FINDING_CATEGORIES.map((category) => {
          const id = `${idPrefix}-${category}`;
          return (
            <label key={category} htmlFor={id} className="chip">
              <input
                id={id}
                type="checkbox"
                checked={value.includes(category)}
                onChange={() => toggle(category)}
              />
              <span>{labelize(category)}</span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
