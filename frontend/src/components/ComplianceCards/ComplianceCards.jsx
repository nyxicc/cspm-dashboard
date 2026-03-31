import { useMemo } from 'react';
import ServiceCard  from './ServiceCard';
import ErrorBanner  from '../shared/ErrorBanner/ErrorBanner';
import { deriveServiceCards, KNOWN_SERVICES } from '../../utils/compliance';
import styles from './ComplianceCards.module.css';

export default function ComplianceCards({ findings, loading, error }) {
  // deriveServiceCards iterates the full findings array — wrap in useMemo so
  // it only reruns when findings actually changes, not on every parent render.
  const cards = useMemo(() => deriveServiceCards(findings), [findings]);

  if (error) return <ErrorBanner message={error} />;

  if (loading) {
    return (
      <div className={styles.grid}>
        {KNOWN_SERVICES.map(s => (
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
