import styles from './ErrorBanner.module.css';

export default function ErrorBanner({ message }) {
  return (
    <div className={styles.banner} role="alert">
      <span className={styles.icon}>!</span>
      <div>
        <p className={styles.heading}>Failed to load data</p>
        {message && <p className={styles.message}>{message}</p>}
      </div>
    </div>
  );
}
