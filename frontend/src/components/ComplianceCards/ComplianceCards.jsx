import { useMemo } from 'react';
import ServiceCard  from './ServiceCard';
import ErrorBanner  from '../shared/ErrorBanner/ErrorBanner';
import { deriveServiceCards, AWS_SERVICES, AZURE_SERVICES } from '../../utils/compliance';
import styles from './ComplianceCards.module.css';

export default function ComplianceCards({ findings, loading, error, provider }) {
  const serviceList = provider === 'azure' ? AZURE_SERVICES : AWS_SERVICES;

  // deriveServiceCards iterates the full findings array — wrap in useMemo so
  // it only reruns when findings or provider actually changes.
  const cards = useMemo(
    () => deriveServiceCards(findings, serviceList),
    [findings, serviceList],
  );

  if (error) return <ErrorBanner message={error} />;

  if (loading) {
    return (
      <div className={styles.grid}>
        {serviceList.map(s => (
          <div key={s} className={`${styles.skeletonCard} skeleton`} />
        ))}
      </div>
    );
  }

  return (
    <div className={styles.grid}>
      {cards.map(card => (
        <ServiceCard key={card.service} {...card} />
      ))}
    </div>
  );
}
