import { useCallback, useEffect, useRef, useState } from "react";

import { api, type Query } from "./api";

export interface Loaded<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  reload: () => void;
}

/**
 * GET a JSON resource. Re-fetches when the path or query changes. If `pollWhile`
 * returns true for the latest data, it is fetched again every `pollMs`.
 */
export function useApi<T>(
  path: string | null,
  query?: Query,
  options: { pollMs?: number; pollWhile?: (data: T) => boolean } = {},
): Loaded<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<Error>();
  const [loading, setLoading] = useState(false);
  const [tick, setTick] = useState(0);
  const key = path === null ? null : `${path}?${JSON.stringify(query ?? {})}`;
  const pollWhile = useRef(options.pollWhile);
  pollWhile.current = options.pollWhile;

  useEffect(() => {
    if (key === null || path === null) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    setLoading(true);
    api<T>(path, { query, signal: controller.signal })
      .then((value) => {
        setData(value);
        setError(undefined);
        if (options.pollMs && pollWhile.current?.(value)) {
          timer = setTimeout(() => setTick((n) => n + 1), options.pollMs);
        }
      })
      .catch((exc: Error) => {
        if (exc.name !== "AbortError") setError(exc);
      })
      .finally(() => setLoading(false));
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  return { data, error, loading, reload };
}
