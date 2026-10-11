import { useState } from 'react'
import { Copy, Search, X } from 'lucide-react'
import {
  Button,
  Checkbox,
  Chip,
  ConfidenceMeter,
  CountChip,
  IconButton,
  Input,
  Kbd,
  MenuCheckItem,
  MenuItem,
  Popover,
  PopoverContent,
  PopoverTrigger,
  SegmentedControl,
  SeverityDot,
  SeverityLabel,
  StatusBadge,
  Tag,
  Textarea,
  Tooltip,
  ValueChip,
} from '../components/ui'
import { cn } from '../lib/utils'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
const CONF = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const

/** Phase 1 deliverable: every primitive, every state, on one page. */
export default function Kitchen() {
  const [sev, setSev] = useState<(typeof SEVERITIES)[number]>('HIGH')
  const [conf, setConf] = useState<(typeof CONF)[number]>('HIGH')
  const [check, setCheck] = useState<boolean | 'indeterminate'>('indeterminate')
  const [cols, setCols] = useState({ ioc: true, type: true, severity: false })

  return (
    <div className="mx-auto max-w-[1000px] space-y-8 px-6 py-8">
      <header className="border-b border-line pb-4">
        <h1 className="text-[20px] font-semibold tracking-[-0.01em]">Kitchen sink</h1>
        <p className="text-[13px] text-fg-muted">Phase 1 primitives and states.</p>
      </header>

      <Section title="Buttons">
        <Row>
          <Button variant="primary">Primary</Button>
          <Button>Ghost</Button>
          <Button variant="danger">Danger</Button>
          <Button size="sm">Small</Button>
          <Button disabled>Disabled</Button>
        </Row>
        <Row>
          <IconButton label="Refresh"><Copy /></IconButton>
          <IconButton label="Close" size="sm"><X /></IconButton>
          <Tooltip content="Tooltips explain unfamiliar icons">
            <IconButton label="Help"><Search /></IconButton>
          </Tooltip>
        </Row>
      </Section>

      <Section title="Inputs">
        <Row>
          <Input placeholder="Search IOCs" className="max-w-[260px]" />
          <Input placeholder="With icon" icon={<Search />} className="max-w-[260px]" />
          <Input placeholder="With kbd hint" suffix={<Kbd>/</Kbd>} className="max-w-[260px]" />
        </Row>
        <Row>
          <Textarea rows={3} placeholder="Description" className="max-w-[420px]" />
        </Row>
        <Row>
          <Checkbox state={check} onChange={(v) => setCheck(v)} label="Select all" />
          <Checkbox state={true} onChange={() => {}} label="Checked" />
          <Checkbox state={false} onChange={() => {}} label="Unchecked" />
        </Row>
      </Section>

      <Section title="Severity and status">
        <Row>
          {SEVERITIES.map((s) => (
            <span key={s} className="inline-flex items-center gap-3">
              <SeverityLabel severity={s} />
              <span className="inline-flex items-center gap-1.5">
                <SeverityDot severity={s} />
                <span className="font-mono text-[12px] text-fg-muted">{s}</span>
              </span>
            </span>
          ))}
        </Row>
        <Row>
          {CONF.map((c) => (
            <ConfidenceMeter key={c} value={c} />
          ))}
          <StatusBadge status="VALID" />
          <StatusBadge status="" />
        </Row>
      </Section>

      <Section title="Tags and chips">
        <Row>
          <Tag>Domain</Tag>
          <Tag mono>SHA256</Tag>
          <Chip label="severity: HIGH" onRemove={() => {}} />
          <Chip label="folder: php.shin_webshell" onRemove={() => {}} />
          <ValueChip label="C2" onRemove={() => {}} />
          <CountChip n={7} />
        </Row>
      </Section>

      <Section title="Segmented control">
        <Row>
          <SegmentedControl
            ariaLabel="Severity"
            value={sev}
            onChange={setSev}
            options={SEVERITIES.map((s) => ({ value: s, label: s }))}
          />
          <SegmentedControl
            ariaLabel="Confidence"
            value={conf}
            onChange={setConf}
            options={CONF.map((c) => ({ value: c, label: c }))}
          />
        </Row>
      </Section>

      <Section title="Popover and menu">
        <Row>
          <Popover>
            <PopoverTrigger asChild>
              <Button>Open popover</Button>
            </PopoverTrigger>
            <PopoverContent className="w-[200px]">
              <MenuItem onSelect={() => {}}>Refresh folders</MenuItem>
              <MenuItem onSelect={() => {}}>Group by parent domain</MenuItem>
              <div className="my-1 border-t border-line" />
              <MenuCheckItem
                checked={cols.ioc}
                onSelect={() => setCols((c) => ({ ...c, ioc: !c.ioc }))}
              >
                IOC
              </MenuCheckItem>
              <MenuCheckItem
                checked={cols.severity}
                onSelect={() => setCols((c) => ({ ...c, severity: !c.severity }))}
              >
                Severity
              </MenuCheckItem>
              <div className="my-1 border-t border-line" />
              <MenuItem destructive onSelect={() => {}}>
                Delete selection
              </MenuItem>
            </PopoverContent>
          </Popover>
        </Row>
      </Section>

      <Section title="Table row states">
        <div className="overflow-hidden rounded-panel border border-line">
          {(['default', 'hover', 'selected'] as const).map((s) => (
            <div
              key={s}
              className={cn(
                'flex h-8 items-center gap-3 border-b border-line px-3 text-[13px] last:border-b-0',
                s === 'hover' && 'bg-surface-2',
                s === 'selected' && 'bg-surface-3 shadow-[inset_2px_0_0_var(--color-accent)]',
              )}
            >
              <span className="font-mono text-fg">1.2.3.4</span>
              <Tag>IPv4</Tag>
              <SeverityLabel severity="CRITICAL" />
              <span className="text-[12px] text-fg-subtle">{s}</span>
            </div>
          ))}
        </div>
      </Section>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="label-xs mb-3">{title}</h2>
      <div className="space-y-3">{children}</div>
    </section>
  )
}

function Row({ children }: { children: React.ReactNode }) {
  return <div className="flex flex-wrap items-center gap-2">{children}</div>
}
