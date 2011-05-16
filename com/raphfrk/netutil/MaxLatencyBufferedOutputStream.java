package com.raphfrk.netutil;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

import com.raphfrk.protocol.KillableThread;

public class MaxLatencyBufferedOutputStream extends BufferedOutputStream {

	private final long maxLatency;
	private final AtomicLong nextFlush = new AtomicLong(0L);
	private final ReentrantLock lock = new ReentrantLock();
	private final Object syncObj = new Object();
	private final LocalTimer timer = new LocalTimer();

	public MaxLatencyBufferedOutputStream(OutputStream out) {
		this(out, 512, 50);
	}

	public MaxLatencyBufferedOutputStream(OutputStream out, int size, long maxLatency) {
		super(out, size);
		this.maxLatency = maxLatency;
		timer.start();
	}

	private void pingFlush() {
		if(nextFlush.compareAndSet(0, System.currentTimeMillis() + maxLatency)) {
			synchronized(syncObj) {
				//System.out.println("Notifying");
				syncObj.notifyAll();
			}
		}
	}

	private void clearFlush() {
		nextFlush.set(0);
	}

	@Override
	public void write(int b) throws IOException {
		lock.lock();
		try {
			super.write(b);
		} finally {
			lock.unlock();
		}
		pingFlush();
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		lock.lock();
		try {
			super.write(b, off, len);
		} finally {
			lock.unlock();
		}
		pingFlush();
	}

	public void flush() throws IOException {
		clearFlush();

		lock.lock();
		try {
			super.flush();
		} finally {
			lock.unlock();
		}
	}

	public void close() throws IOException {

		while(timer.isAlive()) {
			timer.interrupt();
			try {
				timer.join(50);
			} catch (InterruptedException ie) {
				try {
					Thread.currentThread().interrupt();
					Thread.sleep(50);
				} catch (InterruptedException ie2) {
					Thread.currentThread().interrupt();
				}
			}

		}

	}

	private class LocalTimer extends KillableThread {

		public void run() {

			while(!killed()) {

				long nextFlushLocal = nextFlush.get();

				long currentTime = System.currentTimeMillis();

				if(nextFlushLocal != 0 && nextFlushLocal + maxLatency < currentTime) {

					if(lock.tryLock()) {
						try {
							flush();
						} catch (IOException e) {
						} finally {
							lock.unlock();
						}
					} else {
						//System.out.println("Lock failed");
					}

				}

				synchronized(syncObj) {
					nextFlushLocal = nextFlush.get();
					currentTime = System.currentTimeMillis();

					long delay = Math.max(10L, Math.min(maxLatency, nextFlushLocal - currentTime));
					try {
						if(nextFlushLocal == 0 ) {
							//System.out.println("Waiting 500");
							syncObj.wait(500);
						} else {
							//System.out.println("Waiting " + delay);
							syncObj.wait(delay);
						} 
					} catch (InterruptedException ie) {
						kill();
						continue;
					}
				}
			}
		}
	}
}