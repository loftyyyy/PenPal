import { FINDING_CATEGORIES, type FindingCategory } from "../lib/types";
import { labelize } from "../lib/format";
import { InfoTip } from "./InfoTip";

export function CategoryPicker({
  value,
  onChange,
  idPrefix = "category",
  help = "Choose the security areas this assessment covers. These guide test planning and reporting; you can change them later.",
}: {
  value: FindingCategory[];
  onChange: (value: FindingCategory[]) => void;
  idPrefix?: string;
  help?: string;
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
      <legend>
        Assessment categories
        <InfoTip label="Assessment categories">{help}</InfoTip>
      </legend>
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
