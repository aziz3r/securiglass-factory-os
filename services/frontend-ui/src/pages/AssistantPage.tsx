import { PageHeader } from '../components/PageHeader';
import { useLocale } from '../i18n/i18n';
import { AssistantPanel } from './dashboard/panels';

export function AssistantPage() {
  const { t } = useLocale();
  return (
    <div className="page">
      <PageHeader
        eyebrow={t('assistant.eyebrow')}
        title={t('assistant.title')}
        description={t('assistant.description')}
      />
      <div className="assistant-wrap">
        <AssistantPanel />
      </div>
    </div>
  );
}
