import { useCallback, useEffect, useRef, useState } from "react";

export function useAsync(loader, dependencies = []) {
  const mounted = useRef(false);
  const [state, setState] = useState({
    status: "loading",
    data: null,
    error: null,
    refreshing: false,
  });
  const [revision, setRevision] = useState(0);
  const retry = useCallback(() => {
    if (mounted.current) setRevision((value) => value + 1);
  }, []);

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    setState((current) => ({
      ...current,
      status: current.data ? "success" : "loading",
      error: null,
      refreshing: Boolean(current.data),
    }));
    loader(controller.signal)
      .then(
        (data) =>
          !controller.signal.aborted &&
          setState({ status: "success", data, error: null, refreshing: false }),
      )
      .catch(
        (error) =>
          !controller.signal.aborted &&
          setState((current) =>
            current.data
              ? { ...current, error, refreshing: false }
              : { status: "error", data: null, error, refreshing: false },
          ),
      );
    return () => {
      mounted.current = false;
      controller.abort();
    };
  }, [revision, ...dependencies]);

  return { ...state, retry };
}
