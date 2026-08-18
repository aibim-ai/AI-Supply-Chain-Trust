import { useEffect } from "react";
import { applyDocumentMeta } from "../lib/seo";

/**
 * Writes the route's document metadata on mount and whenever the described
 * metadata changes (route params, loaded payloads). The descriptor is compared
 * by value so callers do not need to memoize it.
 */
export function useDocumentMeta(meta) {
  const serialized = JSON.stringify(meta ?? {});
  useEffect(() => {
    applyDocumentMeta(JSON.parse(serialized));
  }, [serialized]);
}
