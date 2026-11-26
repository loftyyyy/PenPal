import { Link } from "react-router-dom";
import { EmptyState } from "../components/ui";

export function NotFoundPage() {
  return (
    <div className="page">
      <EmptyState
        title="Page not found"
        description="The page you requested does not exist."
        action={
          <Link to="/assessments" className="btn btn-primary">
            Go to assessments
          </Link>
        }
      />
    </div>
  );
}
