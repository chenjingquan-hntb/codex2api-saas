import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  ChevronDown,
  CreditCard,
  Globe,
  Loader2,
  Mail,
  Save,
  Send,
  ShieldCheck,
  Wallet,
} from 'lucide-react'
import { controlSettings } from '../api'
import type { ControlSettings, ControlSettingSection } from '../types'
import PageHeader from '../components/PageHeader'
import StateShell from '../components/StateShell'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Select } from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { useToast } from '../hooks/useToast'
import { getErrorMessage } from '../utils/error'

// 微元 → 元（计费金额以微元存储，管理页用「元」编辑）
const MICRO_PER_YUAN = 10_000_000

function microToYuan(micro: number): string {
  return (micro / MICRO_PER_YUAN).toFixed(7).replace(/0+$/, '').replace(/\.$/, '')
}

function yuanToMicro(s: string): number {
  const n = Number(s)
  if (!Number.isFinite(n) || n < 0) return 0
  return Math.round(n * MICRO_PER_YUAN)
}

type SectionKey = 'billing' | 'smtp' | 'epay' | 'turnstile' | 'geoip'

const SECTION_META: Record<
  SectionKey,
  { title: string; desc: string; icon: React.ReactNode; section: ControlSettingSection }
> = {
  billing: {
    title: '钱包计费',
    desc: '为 /v1/* 请求预留/结算钱包额度。开启后，用户归属的 API Key 请求需有足够余额。',
    icon: <Wallet className="size-4.5" />,
    section: 'billing',
  },
  smtp: {
    title: 'SMTP 邮件',
    desc: '发送邮箱验证 / 密码重置邮件。未启用时验证与重置链接打印在服务日志中（dev URL）。',
    icon: <Mail className="size-4.5" />,
    section: 'smtp',
  },
  epay: {
    title: '易支付',
    desc: '钱包充值网关。配置商户号与密钥后，用户可在门户发起充值。',
    icon: <CreditCard className="size-4.5" />,
    section: 'epay',
  },
  turnstile: {
    title: 'Turnstile 人机校验',
    desc: 'Cloudflare Turnstile，用于注册/登录防自动化。',
    icon: <ShieldCheck className="size-4.5" />,
    section: 'turnstile',
  },
  geoip: {
    title: 'GeoIP 地理准入',
    desc: '按国家/地区限制访问（数据面或门户）。',
    icon: <Globe className="size-4.5" />,
    section: 'geoip',
  },
}

function SectionCard({
  section,
  title,
  desc,
  icon,
  children,
  onSave,
  saving,
}: {
  section: SectionKey
  title: string
  desc: string
  icon: React.ReactNode
  children: React.ReactNode
  onSave: () => void
  saving: boolean
}) {
  const [open, setOpen] = useState(false)
  return (
    <Card className="gap-0 py-0">
      <CardContent className="p-0">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="flex w-full items-center gap-3 px-5 py-4 text-left"
        >
          <span className="text-muted-foreground">{icon}</span>
          <span className="flex-1">
            <span className="block text-sm font-semibold">{title}</span>
            <span className="mt-0.5 block text-xs text-muted-foreground">{desc}</span>
          </span>
          <ChevronDown className={cn('size-4 text-muted-foreground transition-transform', open && 'rotate-180')} />
        </button>
        {open && (
          <div className="space-y-4 border-t px-5 py-4">
            {children}
            <div className="flex items-center justify-end gap-2">
              <Button size="sm" onClick={onSave} disabled={saving}>
                {saving ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />}
                保存
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
      {hint ? <span className="block text-[11px] text-muted-foreground/80">{hint}</span> : null}
    </label>
  )
}

export default function ControlPanel() {
  const { showToast } = useToast()
  const [data, setData] = useState<ControlSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [drafts, setDrafts] = useState<Record<string, Record<string, unknown>>>({})
  const [saving, setSaving] = useState<SectionKey | null>(null)
  const [smtpTestTo, setSmtpTestTo] = useState('')
  const [smtpTesting, setSmtpTesting] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await controlSettings.get()
      setData(res)
      setDrafts({
        billing: { ...res.billing },
        smtp: { ...res.smtp },
        epay: { ...res.epay },
        turnstile: { ...res.turnstile },
        geoip: { ...res.geoip },
      })
      setError(null)
    } catch (e) {
      setError(getErrorMessage(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const draft = useMemo(
    () => (section: SectionKey) => drafts[section] ?? {},
    [drafts],
  )

  const patch = (section: SectionKey, patchValue: Record<string, unknown>) => {
    setDrafts((prev) => ({ ...prev, [section]: { ...prev[section], ...patchValue } }))
  }

  const save = async (section: SectionKey) => {
    setSaving(section)
    try {
      const res = await controlSettings.update(SECTION_META[section].section, draft(section))
      setData((prev) => (prev ? { ...prev, [section]: res.value as never } : prev))
      setDrafts((prev) => ({ ...prev, [section]: { ...res.value } }))
      showToast('已保存')
    } catch (e) {
      showToast(getErrorMessage(e), 'error')
    } finally {
      setSaving(null)
    }
  }

  const testSMTP = async () => {
    if (!smtpTestTo.trim()) {
      showToast('请填写测试收件邮箱', 'error')
      return
    }
    setSmtpTesting(true)
    try {
      await controlSettings.testSMTP(smtpTestTo.trim())
      showToast('测试邮件已发送')
    } catch (e) {
      showToast(getErrorMessage(e), 'error')
    } finally {
      setSmtpTesting(false)
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <PageHeader
        title="控制面配置"
        description="钱包计费、邮件、支付网关与人机校验（P5/P6）"
        onRefresh={load}
        refreshLabel="刷新"
      />
      {loading ? (
        <StateShell loading>
          <div />
        </StateShell>
      ) : error ? (
        <StateShell error={error} onRetry={load}>
          <div />
        </StateShell>
      ) : (
        <div className="space-y-4">
          <SectionCard
            section="billing"
            title={SECTION_META.billing.title}
            desc={SECTION_META.billing.desc}
            icon={SECTION_META.billing.icon}
            saving={saving === 'billing'}
            onSave={() => save('billing')}
          >
            <div className="flex items-center justify-between gap-3">
              <Field label="启用钱包计费">
                <Switch
                  checked={Boolean(draft('billing').enabled)}
                  onCheckedChange={(v) => patch('billing', { enabled: v })}
                />
              </Field>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="每请求预留额度（元）" hint="请求开始时预扣，成功后按实际用量多退少补">
                <Input
                  type="number"
                  min={0}
                  value={microToYuan(Number(draft('billing').deposit_micro ?? 0))}
                  onChange={(e) => patch('billing', { deposit_micro: yuanToMicro(e.target.value) })}
                />
              </Field>
              <Field label="最小扣费（元/请求）" hint="有实际用量时每请求至少扣这么多">
                <Input
                  type="number"
                  min={0}
                  value={microToYuan(Number(draft('billing').min_charge_micro ?? 0))}
                  onChange={(e) => patch('billing', { min_charge_micro: yuanToMicro(e.target.value) })}
                />
              </Field>
              <Field label="单请求扣费封顶（元，0=不封顶）">
                <Input
                  type="number"
                  min={0}
                  value={microToYuan(Number(draft('billing').charge_cap_micro ?? 0))}
                  onChange={(e) => patch('billing', { charge_cap_micro: yuanToMicro(e.target.value) })}
                />
              </Field>
              <Field label="汇率倍率（美元成本 × 倍率 = 人民币收费）">
                <Input
                  type="number"
                  min={0}
                  step={0.1}
                  value={Number(draft('billing').cny_per_usd ?? 0)}
                  onChange={(e) => patch('billing', { cny_per_usd: Number(e.target.value) })}
                />
              </Field>
            </div>
          </SectionCard>

          <SectionCard
            section="smtp"
            title={SECTION_META.smtp.title}
            desc={SECTION_META.smtp.desc}
            icon={SECTION_META.smtp.icon}
            saving={saving === 'smtp'}
            onSave={() => save('smtp')}
          >
            <div className="flex items-center justify-between gap-3">
              <Field label="启用 SMTP">
                <Switch
                  checked={Boolean(draft('smtp').enabled)}
                  onCheckedChange={(v) => patch('smtp', { enabled: v })}
                />
              </Field>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="主机">
                <Input value={String(draft('smtp').host ?? '')} onChange={(e) => patch('smtp', { host: e.target.value })} />
              </Field>
              <Field label="端口">
                <Input
                  type="number"
                  value={Number(draft('smtp').port ?? 587)}
                  onChange={(e) => patch('smtp', { port: Number(e.target.value) })}
                />
              </Field>
              <Field label="安全模式">
                <Select
                  value={String(draft('smtp').security ?? 'starttls')}
                  onValueChange={(v) => patch('smtp', { security: v })}
                  options={[
                    { value: 'starttls', label: 'STARTTLS（587）' },
                    { value: 'ssl', label: 'SSL（465）' },
                    { value: 'none', label: '无（明文，仅内网调试）' },
                  ]}
                />
              </Field>
              <Field label="用户名">
                <Input value={String(draft('smtp').username ?? '')} onChange={(e) => patch('smtp', { username: e.target.value })} />
              </Field>
              <Field label="密码">
                <Input type="password" value={String(draft('smtp').password ?? '')} onChange={(e) => patch('smtp', { password: e.target.value })} />
              </Field>
              <Field label="发件人地址（from）">
                <Input value={String(draft('smtp').from ?? '')} onChange={(e) => patch('smtp', { from: e.target.value })} />
              </Field>
              <Field label="发件人名称">
                <Input value={String(draft('smtp').from_name ?? '')} onChange={(e) => patch('smtp', { from_name: e.target.value })} />
              </Field>
              <div className="flex items-end gap-2">
                <Field label="测试收件邮箱">
                  <Input
                    value={smtpTestTo}
                    onChange={(e) => setSmtpTestTo(e.target.value)}
                    placeholder="test@example.com"
                  />
                </Field>
                <Button variant="secondary" size="sm" onClick={testSMTP} disabled={smtpTesting}>
                  {smtpTesting ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
                  发送测试
                </Button>
              </div>
            </div>
          </SectionCard>

          <SectionCard
            section="epay"
            title={SECTION_META.epay.title}
            desc={SECTION_META.epay.desc}
            icon={SECTION_META.epay.icon}
            saving={saving === 'epay'}
            onSave={() => save('epay')}
          >
            <div className="flex items-center justify-between gap-3">
              <Field label="启用易支付">
                <Switch
                  checked={Boolean(draft('epay').enabled)}
                  onCheckedChange={(v) => patch('epay', { enabled: v })}
                />
              </Field>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="商户号">
                <Input value={String(draft('epay').merchant_id ?? '')} onChange={(e) => patch('epay', { merchant_id: e.target.value })} />
              </Field>
              <Field label="密钥">
                <Input type="password" value={String(draft('epay').key ?? '')} onChange={(e) => patch('epay', { key: e.target.value })} />
              </Field>
              <Field label="网关地址" hint="如 https://pay.example.com/submit.php">
                <Input value={String(draft('epay').gateway_url ?? '')} onChange={(e) => patch('epay', { gateway_url: e.target.value })} />
              </Field>
              <Field label="本站对外根地址" hint="用于拼通知/回跳 URL">
                <Input value={String(draft('epay').callback_base_url ?? '')} onChange={(e) => patch('epay', { callback_base_url: e.target.value })} />
              </Field>
            </div>
          </SectionCard>

          <SectionCard
            section="turnstile"
            title={SECTION_META.turnstile.title}
            desc={SECTION_META.turnstile.desc}
            icon={SECTION_META.turnstile.icon}
            saving={saving === 'turnstile'}
            onSave={() => save('turnstile')}
          >
            <div className="flex items-center justify-between gap-3">
              <Field label="启用 Turnstile">
                <Switch
                  checked={Boolean(draft('turnstile').enabled)}
                  onCheckedChange={(v) => patch('turnstile', { enabled: v })}
                />
              </Field>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="站点密钥（Site Key）">
                <Input value={String(draft('turnstile').site_key ?? '')} onChange={(e) => patch('turnstile', { site_key: e.target.value })} />
              </Field>
              <Field label="密钥（Secret Key）">
                <Input type="password" value={String(draft('turnstile').secret_key ?? '')} onChange={(e) => patch('turnstile', { secret_key: e.target.value })} />
              </Field>
            </div>
          </SectionCard>

          <SectionCard
            section="geoip"
            title={SECTION_META.geoip.title}
            desc={SECTION_META.geoip.desc}
            icon={SECTION_META.geoip.icon}
            saving={saving === 'geoip'}
            onSave={() => save('geoip')}
          >
            <div className="flex items-center justify-between gap-3">
              <Field label="启用 GeoIP">
                <Switch
                  checked={Boolean(draft('geoip').enabled)}
                  onCheckedChange={(v) => patch('geoip', { enabled: v })}
                />
              </Field>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="服务商">
                <Select
                  value={String(draft('geoip').provider ?? '')}
                  onValueChange={(v) => patch('geoip', { provider: v })}
                  options={[
                    { value: '', label: '未选择' },
                    { value: 'maxmind', label: 'MaxMind GeoLite2' },
                    { value: 'ipinfo', label: 'IPinfo' },
                  ]}
                />
              </Field>
              <Field label="API Key">
                <Input type="password" value={String(draft('geoip').api_key ?? '')} onChange={(e) => patch('geoip', { api_key: e.target.value })} />
              </Field>
              <Field label="模式">
                <Select
                  value={String(draft('geoip').mode ?? 'block')}
                  onValueChange={(v) => patch('geoip', { mode: v })}
                  options={[
                    { value: 'block', label: '黑名单：名单内国家拒绝' },
                    { value: 'allow', label: '白名单：仅名单内国家放行' },
                  ]}
                />
              </Field>
              <Field label="国家列表" hint="ISO 3166-1 alpha-2，逗号分隔，如 cn,us">
                <Input
                  value={(Array.isArray(draft('geoip').countries) ? (draft('geoip').countries as string[]).join(',') : '').toUpperCase()}
                  onChange={(e) =>
                    patch('geoip', {
                      countries: e.target.value
                        .split(',')
                        .map((s) => s.trim().toUpperCase())
                        .filter(Boolean),
                    })
                  }
                />
              </Field>
              <Field label="缓存时长（分钟）">
                <Input
                  type="number"
                  min={1}
                  value={Number(draft('geoip').cache_ttl_minutes ?? 60)}
                  onChange={(e) => patch('geoip', { cache_ttl_minutes: Number(e.target.value) })}
                />
              </Field>
            </div>
          </SectionCard>
        </div>
      )}
    </div>
  )
}
