import type { PluginContext, CronEvent, LifecycleEvent } from 'emdash/plugin';

export async function scheduleProbe(_event: LifecycleEvent, ctx: PluginContext): Promise<void> {
  await ctx.cron?.schedule('probe-tick', { schedule: '* * * * *' });
}

export async function recordProbeTick(event: CronEvent, ctx: PluginContext): Promise<void> {
  await ctx.kv.set('probe:cron', { name: event.name, scheduledAt: event.scheduledAt });
  ctx.log.info('Local scheduled probe completed', { name: event.name });
}
