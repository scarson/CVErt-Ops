// ABOUTME: Chooses the badge variant for a feed fetch log status.
// ABOUTME: A partial run stopped at the job time limit and continues, so it is neutral, not an error.

export function feedLogBadgeVariant(status: string): 'default' | 'secondary' | 'destructive' {
  if (status === 'success') return 'default'
  if (status === 'partial') return 'secondary'
  return 'destructive'
}
