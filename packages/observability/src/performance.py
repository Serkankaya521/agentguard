def percentiles(samples_us):
    values = sorted(float(x) for x in samples_us)
    if not values:
        raise ValueError("samples required")
    def p(q):
        return values[min(len(values)-1, round((len(values)-1)*q))]
    return {"p50_us":p(.50),"p95_us":p(.95),"p99_us":p(.99),"max_us":values[-1]}


def runtime_slo_passes(result):
    return (result["p50_us"] < 2000 and result["p95_us"] < 5000
            and result["p99_us"] < 10000 and result["max_us"] < 20000)
