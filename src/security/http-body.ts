export async function readBoundedBody(response: Response, maxBytes: number): Promise<Uint8Array | null> {
	if (!response.body) return null;
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		while (true) {
			const result = await reader.read();
			if (result.done) break;
			if (!(result.value instanceof Uint8Array)) return null;
			total += result.value.byteLength;
			if (total > maxBytes) {
				await reader.cancel();
				return null;
			}
			chunks.push(result.value);
		}
	} catch {
		return null;
	} finally {
		reader.releaseLock();
	}
	const output = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
	return output;
}

export async function cancelBody(response: Response): Promise<void> {
	try { await response.body?.cancel(); } catch { /* refusal is still bounded and remains unknown */ }
}
