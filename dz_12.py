import pyshark
import argparse
import csv
from collections import Counter, defaultdict
from datetime import datetime

import matplotlib.pyplot as plt
import seaborn as sns


def load_pcap(pcap_path):
    """
    Загрузка pcap-файла с помощью pyshark.
    """
    print(f"[+] Загрузка pcap: {pcap_path}")
    capture = pyshark.FileCapture(
        pcap_path,
        display_filter="dns",  # сразу фильтруем по DNS, чтобы ускорить
        keep_packets=False
    )
    return capture


def extract_dns_events(capture):
    """
    Извлечь DNS-запросы: время, src_ip, dst_ip, queried_domain.
    """
    dns_events = []
    domain_counter = Counter()
    ip_counter = Counter()
    time_bins = defaultdict(int)

    for pkt in capture:
        try:
            if 'DNS' not in pkt:
                continue

            timestamp = float(pkt.sniff_timestamp)
            ts = datetime.fromtimestamp(timestamp)

            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None

            # DNS layer
            dns_layer = pkt.dns
            # интересуемся только запросами (qr == 0)
            if hasattr(dns_layer, 'flags_response') and dns_layer.flags_response == '0':
                # qry_name может быть несколько, берем первый
                domain = str(dns_layer.qry_name) if hasattr(dns_layer, 'qry_name') else None
                if not domain:
                    continue

                dns_events.append({
                    "timestamp": ts.isoformat(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "domain": domain
                })

                domain_counter[domain] += 1
                if src_ip:
                    ip_counter[src_ip] += 1

                # округлим время до минут для агрегирования
                time_bin = ts.replace(second=0, microsecond=0)
                time_bins[time_bin] += 1

        except Exception as e:
            # пропускаем пакеты с ошибками парсинга
            print(f"[!] Ошибка обработки пакета: {e}")
            continue

    return dns_events, domain_counter, ip_counter, time_bins


def save_to_csv(dns_events, csv_path="dns_events.csv"):
    """
    Сохранение событий DNS в CSV.
    """
    print(f"[+] Сохранение DNS событий в {csv_path}")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "src_ip", "dst_ip", "domain"])
        writer.writeheader()
        for row in dns_events:
            writer.writerow(row)


def plot_dns_over_time(time_bins, output_path="dns_over_time.png"):
    """
    График количества DNS-запросов по времени (по минутам).
    """
    if not time_bins:
        print("[!] Нет данных для графика DNS по времени.")
        return

    times = sorted(time_bins.keys())
    counts = [time_bins[t] for t in times]

    sns.set(style="whitegrid")
    plt.figure(figsize=(10, 5))
    plt.plot(times, counts, marker="o")
    plt.title("Количество DNS-запросов по времени")
    plt.xlabel("Время (округлено до минуты)")
    plt.ylabel("Количество запросов")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"[+] График DNS по времени сохранён в {output_path}")


def print_top_suspicious(domain_counter, ip_counter, top_n=10):
    """
    Печать топ-10 доменов и IP по числу запросов.
    (Вы можете вручную отметить подозрительные при анализе.)
    """
    print("\n=== Топ доменов по числу DNS-запросов ===")
    for domain, count in domain_counter.most_common(top_n):
        print(f"{domain:50}  {count}")

    print("\n=== Топ источников по числу DNS-запросов ===")
    for ip, count in ip_counter.most_common(top_n):
        print(f"{ip:20}  {count}")


def main():
    parser = argparse.ArgumentParser(description="Анализ сетевого дампа (PCAP) для DNS с помощью pyshark.")
    parser.add_argument("pcap", help="Путь к pcap-файлу (сетевой дамп)")
    parser.add_argument("--csv", default="dns_events.csv", help="Файл для сохранения DNS событий (CSV)")
    parser.add_argument("--png", default="dns_over_time.png", help="Файл для сохранения графика DNS по времени (PNG)")
    args = parser.parse_args()

    capture = load_pcap(args.pcap)
    dns_events, domain_counter, ip_counter, time_bins = extract_dns_events(capture)

    print(f"[+] Всего DNS-запросов: {len(dns_events)}")

    save_to_csv(dns_events, args.csv)
    plot_dns_over_time(time_bins, args.png)
    print_top_suspicious(domain_counter, ip_counter)


if __name__ == "__main__":
    main()